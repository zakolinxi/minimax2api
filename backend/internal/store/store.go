package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"minimax2api/internal/config"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrAlreadyExists = errors.New("already exists")
)

const (
	stateFile     = "app.json"
	pbkdfRounds   = 120000
	sessionTTL    = 12 * time.Hour
	maxSessions   = 512
	schemaVersion = 1
)

// Store keeps the whole application state in memory and persists it through a
// single background writer. Mutations never touch the disk while holding the
// lock, so a slow or blocked filesystem cannot stall request handling.
//
// Settings is additionally mirrored into an atomic snapshot so callers can read
// it even while they hold mu. This matters because callbacks passed into
// mutation helpers (SaveAccountState, UpdateAccount, ...) run under the write
// lock and legitimately need settings; a plain RWMutex would deadlock there
// since Go's sync.RWMutex is not reentrant.
type Store struct {
	mu       sync.RWMutex
	path     string
	dataDir  string
	state    State
	sessions map[string]time.Time
	onChange []func()

	settings atomic.Value // config.Settings

	dirty  chan struct{}
	flush  chan chan error
	closed chan struct{}
	wg     sync.WaitGroup
	// unsaved reports whether the in-memory state may hold changes the disk
	// has not seen. markDirtyLocked sets it; writeSnapshot clears it just
	// before reading the state, so any mutation landing during the write
	// re-sets it. This is what lets the shutdown path tell a lost final write
	// apart from a completed one, since the dirty channel and the closed
	// channel give the loop no ordering guarantee.
	unsaved atomic.Bool
}

// Open loads (or initialises) the persistent store inside dataDir.
func Open(dataDir, adminUser, adminPassword string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	store := &Store{
		path:     filepath.Join(dataDir, stateFile),
		dataDir:  dataDir,
		sessions: make(map[string]time.Time),
		dirty:    make(chan struct{}, 1),
		flush:    make(chan chan error),
		closed:   make(chan struct{}),
	}

	fresh := false
	raw, err := os.ReadFile(store.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &store.state); err != nil {
			// The file is unreadable, and the next successful write would
			// destroy the only copy of every account, key and audit record.
			// Move it aside first — best effort, the error is returned either
			// way — so the operator can still recover the raw content; the
			// next start then finds no file and reinitialises.
			backup := store.path + fmt.Sprintf(".corrupt-%d", time.Now().UnixNano())
			if renameErr := os.Rename(store.path, backup); renameErr == nil {
				return nil, fmt.Errorf("parse %s: %w (damaged file moved to %s)", store.path, err, backup)
			}
			return nil, fmt.Errorf("parse %s: %w", store.path, err)
		}
	case os.IsNotExist(err):
		fresh = true
	default:
		return nil, fmt.Errorf("read %s: %w", store.path, err)
	}

	// A file written by a newer build may carry fields this build does not
	// know. Loading it anyway would drop those fields on the next write, so
	// refuse instead and leave the file exactly as it is.
	if store.state.Version > schemaVersion {
		return nil, fmt.Errorf(
			"数据文件 %s 由更新版本的程序写入（数据版本 %d，当前支持 %d），拒绝加载以避免字段丢失",
			store.path, store.state.Version, schemaVersion,
		)
	}

	if fresh {
		store.state.Settings = config.DefaultSettings(dataDir)
	}
	store.state.Version = schemaVersion
	// A repair has to be written back, not just applied in memory: leaving the
	// file describing a value the process is not using is exactly how a broken
	// default survived a fix to the default itself. The write is queued here and
	// picked up by the loop started below.
	if store.state.Settings.Normalize(dataDir) {
		store.markDirtyLocked()
	}
	store.settings.Store(store.state.Settings)
	if len(store.state.Models) == 0 {
		store.state.Models = BuiltinModels()
	} else if merged, changed := MergeBuiltinModels(store.state.Models); changed {
		// A catalogue that predates a built-in entry has to be written back for
		// the same reason a repaired setting does: leaving the file describing a
		// shorter list than the process is serving means the next release has to
		// merge it again, and the file never becomes an accurate description of
		// what is running.
		store.state.Models = merged
		store.markDirtyLocked()
	}
	if store.state.Admin.Username == "" {
		if adminUser == "" {
			adminUser = "admin"
		}
		password := adminPassword
		generated := false
		if password == "" {
			password = randomToken(12)
			generated = true
		}
		salt := randomToken(16)
		store.state.Admin = Admin{Username: adminUser, Salt: salt, PasswordHash: hashPassword(password, salt)}
		store.state.Settings.Server.AdminUsername = adminUser
		if err := store.writeSnapshotLocked(); err != nil {
			return nil, err
		}
		if generated {
			fmt.Printf("\n  ⚠ 已生成初始管理员密码：%s\n  用户名：%s\n  请登录后立即在「设置」中修改。\n\n", password, adminUser)
		}
	}
	if err := os.MkdirAll(store.state.Settings.Media.GeneratedDir, 0o755); err != nil {
		return nil, fmt.Errorf("create media dir: %w", err)
	}

	store.wg.Add(1)
	go store.loop()
	return store, nil
}

// loop coalesces mutation signals into disk writes.
func (s *Store) loop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.dirty:
			// Debounce so a burst of mutations results in a single write.
			time.Sleep(40 * time.Millisecond)
			select {
			case <-s.dirty:
			default:
			}
			s.writeSnapshotLogged()
		case reply := <-s.flush:
			reply <- s.writeSnapshot()
		case <-s.closed:
			// Shutdown has to be a real final flush. Close's non-blocking
			// flush and this select give the dirty and closed channels no
			// ordering, so the last change signalled just before Close ran
			// could otherwise sit unsaved forever. Write it if one is owed.
			if s.unsaved.Load() {
				s.writeSnapshotLogged()
			}
			return
		}
	}
}

// writeSnapshotLogged wraps writeSnapshot for the background writer, which
// owns the error rather than returning it to anyone.
func (s *Store) writeSnapshotLogged() {
	if err := s.writeSnapshot(); err != nil {
		log.Printf("持久化失败: %v", err)
	}
}

// writeSnapshot marshals under a read lock and performs file I/O outside of it.
func (s *Store) writeSnapshot() error {
	// The unsaved flag is cleared before the state is read, not after the file
	// is written: a mutation landing in between re-sets the flag and re-queues
	// a write, while clearing it afterwards would swallow a change that arrived
	// mid-write and leave the shutdown path believing everything is on disk.
	s.unsaved.Store(false)
	s.mu.RLock()
	raw, err := json.MarshalIndent(s.state, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		s.unsaved.Store(true)
		return err
	}
	if err := writeFileAtomic(s.path, raw); err != nil {
		s.unsaved.Store(true)
		return err
	}
	return nil
}

// writeSnapshotLocked is only used during bootstrap, before the writer starts.
func (s *Store) writeSnapshotLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, raw)
}

// writeFileAtomic replaces path with raw. The temporary file is flushed to the
// disk with an explicit Sync before the rename: neither POSIX nor Windows
// guarantees that rename ordering implies data ordering, so without the sync a
// power cut between the two steps can leave the state file truncated or stale —
// and this one file is the only copy of every account, key and audit record.
func writeFileAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// On Windows a freshly closed file can stay briefly locked by a scanning
	// antivirus, and the rename then fails with "Access is denied" (or a
	// sharing violation) even though nothing else holds the handle. Retry a
	// few times regardless of the error kind — a permanent failure just costs
	// five quick attempts before surfacing, while a transient one is swallowed.
	// The error MUST travel: a swallowed rename made writeSnapshot report
	// success while the disk kept the previous snapshot, and the final-flush
	// guarantee died with it.
	var renameErr error
	for attempt := 0; attempt < 5; attempt++ {
		renameErr = os.Rename(tmp, path)
		if renameErr == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
	if renameErr != nil {
		_ = os.Remove(tmp)
		return renameErr
	}
	return nil
}

func (s *Store) DataDir() string { return s.dataDir }

// OnChange registers a callback fired after every successful mutation.
func (s *Store) OnChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// unlockAndNotify releases mu and then runs the registered change callbacks.
// Callbacks are invoked only after the lock is dropped so they may safely
// re-enter the store: Go's sync.RWMutex is not reentrant, so a callback that
// reads settings while the write lock is still held would deadlock forever.
func (s *Store) unlockAndNotify() {
	callbacks := make([]func(), len(s.onChange))
	copy(callbacks, s.onChange)
	s.mu.Unlock()
	for _, fn := range callbacks {
		fn()
	}
}

// markDirtyLocked schedules a background write. It never blocks.
func (s *Store) markDirtyLocked() {
	// The flag rides along because the channel alone cannot answer "is
	// anything still unsaved": a signal may be sitting unread in the buffer
	// while the loop is mid-write, and the shutdown path needs to know the
	// difference (see the closed case in loop).
	s.unsaved.Store(true)
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

// Save flushes the current state to disk synchronously.
func (s *Store) Save() error {
	s.mu.Lock()
	callbacks := make([]func(), len(s.onChange))
	copy(callbacks, s.onChange)
	s.mu.Unlock()
	for _, fn := range callbacks {
		fn()
	}

	reply := make(chan error, 1)
	select {
	case s.flush <- reply:
		return <-reply
	case <-s.closed:
		return errors.New("store closed")
	}
}

// Close performs a final flush and stops the background writer.
func (s *Store) Close() error {
	reply := make(chan error, 1)
	select {
	case s.flush <- reply:
		<-reply
	default:
	}
	close(s.closed)
	s.wg.Wait()
	return nil
}

// ---------------------------------------------------------------- admin auth

func hashPassword(password, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	sum := mac.Sum(nil)
	for i := 1; i < pbkdfRounds; i++ {
		mac = hmac.New(sha256.New, sum)
		mac.Write([]byte(password + salt))
		sum = mac.Sum(nil)
	}
	return hex.EncodeToString(sum)
}

// randomToken returns bytes hex-encoded as a token.
//
// crypto/rand failing means the operating system's entropy source is broken.
// Falling back to a timestamp would silently issue guessable admin passwords,
// session tokens and API keys, which is strictly worse than not serving at all,
// so the process fails closed instead.
func randomToken(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable, refusing to derive authentication material: %v", err))
	}
	return hex.EncodeToString(buf)
}

func (s *Store) VerifyPassword(username, password string) bool {
	s.mu.RLock()
	admin := s.state.Admin
	s.mu.RUnlock()
	if admin.Username == "" || subtle.ConstantTimeCompare([]byte(admin.Username), []byte(username)) != 1 {
		return false
	}
	expected := hashPassword(password, admin.Salt)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(admin.PasswordHash)) == 1
}

func (s *Store) SetPassword(username, password string) error {
	if len(password) < 8 {
		return errors.New("密码至少 8 位")
	}
	s.mu.Lock()
	defer s.unlockAndNotify()
	salt := randomToken(16)
	s.state.Admin = Admin{Username: username, Salt: salt, PasswordHash: hashPassword(password, salt)}
	s.state.Settings.Server.AdminUsername = username
	s.markDirtyLocked()
	return nil
}

func (s *Store) AdminProfile() Admin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin
}

// IssueSession creates an admin session token.
func (s *Store) IssueSession() (string, time.Time) {
	token := randomToken(24)
	expires := time.Now().Add(sessionTTL)
	s.mu.Lock()
	// Entries only ever leave this map through an explicit revoke or the sweep
	// below, so it would otherwise grow by one per login for the life of the
	// process. Past a generous bound, drop every expired entry before adding
	// another one; live sessions are never touched, so no active login can be
	// ended by the sweep.
	if len(s.sessions) > maxSessions {
		now := time.Now()
		for old, at := range s.sessions {
			if now.After(at) {
				delete(s.sessions, old)
			}
		}
	}
	s.sessions[token] = expires
	s.mu.Unlock()
	return token, expires
}

func (s *Store) ValidateSession(token string) bool {
	if token == "" {
		return false
	}
	s.mu.RLock()
	expires, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if !time.Now().After(expires) {
		return true
	}
	// The entry is dead; drop it here so the map does not keep every token a
	// browser ever presented until the process exits. Re-check under the write
	// lock in case the map changed in between.
	s.mu.Lock()
	if at, still := s.sessions[token]; still && time.Now().After(at) {
		delete(s.sessions, token)
	}
	s.mu.Unlock()
	return false
}

func (s *Store) RevokeSession(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *Store) RevokeAllSessions() {
	s.mu.Lock()
	s.sessions = make(map[string]time.Time)
	s.mu.Unlock()
}

// ------------------------------------------------------------------ settings

// Settings returns the current runtime configuration. It reads an immutable
// atomic snapshot rather than taking mu, so it is safe to call from inside
// callbacks that already run under the write lock.
func (s *Store) Settings() config.Settings {
	if value := s.settings.Load(); value != nil {
		return value.(config.Settings)
	}
	// Only reachable before Open finishes priming the snapshot.
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Settings
}

func (s *Store) UpdateSettings(apply func(*config.Settings)) error {
	// Build the candidate from a copy of the live settings. Settings is a flat
	// struct of strings, ints and bools with no reference fields, so a plain
	// value copy is a deep copy. Working on the copy means a failure below
	// cannot leave the live state, the published snapshot and the file
	// disagreeing about what the configuration is.
	s.mu.Lock()
	candidate := s.state.Settings
	s.mu.Unlock()

	apply(&candidate)
	candidate.Normalize(s.dataDir)

	// The directory creation is real I/O and stays out of the write lock, as
	// the comment on Store demands. It also runs before the commit: a failure
	// here returns with the state untouched instead of leaving memory changed
	// while the snapshot and the file never learn about it.
	if err := os.MkdirAll(candidate.Media.GeneratedDir, 0o755); err != nil {
		return err
	}

	s.mu.Lock()
	s.state.Settings = candidate
	s.markDirtyLocked()
	// Publish inside the lock so a callback reading settings sees the new value.
	s.settings.Store(candidate)
	defer s.unlockAndNotify()
	return nil
}

// ------------------------------------------------------------------ accounts

// MaskToken renders a token safe for display.
//
// A JWT's first bytes are its base64 header, which is identical for every token
// issued by the same service, so the prefix carries no information. The tail is
// the part that actually differs between accounts, which is why most of the
// visible characters are taken from the end.
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 20 {
		return "••••••"
	}
	return token[:6] + "…" + token[len(token)-10:]
}

// clone returns a deep copy of an account.
//
// The store owns the live account objects and mutates them in place under s.mu.
// Handing those pointers to callers would let them read fields without holding
// the lock, which races with SaveAccountState and friends. Copying is cheap
// here because Account holds only value types apart from Quota.
func (a *Account) clone() *Account {
	if a == nil {
		return nil
	}
	out := *a
	// A cooldown is a deadline, not a mode.
	//
	// release() stamps StatusCooldown together with a CooldownUntil, and nothing
	// flips the status back until the account is used again — so an account that
	// cooled down once and then went idle keeps reporting "cooldown" forever.
	// Every read goes through this snapshot (the admin list, /health), and a
	// stale value there is how a fully recovered pool still gets read as drained.
	if out.Status == StatusCooldown && !time.Now().Before(out.CooldownUntil) {
		out.Status = StatusActive
		out.CooldownUntil = time.Time{}
	}
	if a.Quota != nil {
		quota := *a.Quota
		out.Quota = &quota
	}
	// Credit and SigninPanel are pointers, so the shallow copy above would let a
	// caller mutate the store's own struct without holding the lock — and the
	// panel's slice would share a backing array, so an append on either side
	// could scribble over the other's view.
	if a.Credit != nil {
		credit := *a.Credit
		out.Credit = &credit
	}
	if a.SigninPanel != nil {
		panel := *a.SigninPanel
		panel.Days = append([]SigninDay(nil), a.SigninPanel.Days...)
		out.SigninPanel = &panel
	}
	return &out
}

// ListAccounts returns a detached snapshot of every account. Callers may read
// and even mutate the result without holding any lock and without affecting the
// store; all writes must go through the mutation helpers.
func (s *Store) ListAccounts() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Account, 0, len(s.state.Accounts))
	for _, account := range s.state.Accounts {
		out = append(out, account.clone())
	}
	return out
}

func (s *Store) AccountByID(id string) (*Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, account := range s.state.Accounts {
		if account.ID == id {
			return account.clone(), true
		}
	}
	return nil, false
}

func (s *Store) AddAccount(account *Account) error {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for _, existing := range s.state.Accounts {
		if existing.Token != "" && existing.Token == account.Token {
			return ErrAlreadyExists
		}
	}
	if account.ID == "" {
		account.ID = "acc_" + randomToken(8)
	}
	if account.Kind == "" {
		account.Kind = KindToken
	}
	if account.Region == "" {
		account.Region = RegionGlobal
	}
	if account.Priority <= 0 {
		account.Priority = 50
	}
	if account.MaxConcurrent <= 0 {
		account.MaxConcurrent = 2
	}
	account.Status = StatusActive
	now := time.Now()
	account.CreatedAt = now
	account.UpdatedAt = now
	// The defaults applied above stay on the caller's object (the console reads
	// account.ID right after this returns), but the store keeps its own copy:
	// aliasing the caller's pointers would let anything they do afterwards race
	// with the pool mutating accounts under the lock.
	s.state.Accounts = append(s.state.Accounts, account.clone())
	s.markDirtyLocked()
	return nil
}

func (s *Store) UpdateAccount(id string, apply func(*Account)) (*Account, error) {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for _, account := range s.state.Accounts {
		if account.ID != id {
			continue
		}
		apply(account)
		account.UpdatedAt = time.Now()
		if !account.Enabled {
			account.Status = StatusDisabled
		} else if account.Status == StatusDisabled {
			account.Status = StatusActive
		}
		s.markDirtyLocked()
		// A detached snapshot, like every other read path hands out.
		return account.clone(), nil
	}
	return nil, ErrNotFound
}

func (s *Store) DeleteAccount(id string) error {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for index, account := range s.state.Accounts {
		if account.ID != id {
			continue
		}
		s.state.Accounts = append(s.state.Accounts[:index], s.state.Accounts[index+1:]...)
		s.markDirtyLocked()
		return nil
	}
	return ErrNotFound
}

// DeleteAccounts removes every account whose id is listed and returns the count.
func (s *Store) DeleteAccounts(ids []string) (int, error) {
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.unlockAndNotify()
	kept := make([]*Account, 0, len(s.state.Accounts))
	deleted := 0
	for _, account := range s.state.Accounts {
		if _, ok := wanted[account.ID]; ok {
			deleted++
			continue
		}
		kept = append(kept, account)
	}
	if deleted == 0 {
		return 0, nil
	}
	s.state.Accounts = kept
	s.markDirtyLocked()
	return deleted, nil
}

// DeleteAccountsByStatus removes accounts in any of the given states.
func (s *Store) DeleteAccountsByStatus(statuses []string) (int, error) {
	wanted := make(map[string]struct{}, len(statuses))
	for _, status := range statuses {
		wanted[status] = struct{}{}
	}
	s.mu.Lock()
	defer s.unlockAndNotify()
	kept := make([]*Account, 0, len(s.state.Accounts))
	deleted := 0
	for _, account := range s.state.Accounts {
		if _, ok := wanted[account.Status]; ok {
			deleted++
			continue
		}
		kept = append(kept, account)
	}
	if deleted == 0 {
		return 0, nil
	}
	s.state.Accounts = kept
	s.markDirtyLocked()
	return deleted, nil
}

// UpdateAccounts applies a mutation to every id and persists once.
func (s *Store) UpdateAccounts(ids []string, apply func(*Account)) (int, error) {
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.unlockAndNotify()
	updated := 0
	now := time.Now()
	for _, account := range s.state.Accounts {
		if _, ok := wanted[account.ID]; !ok {
			continue
		}
		apply(account)
		account.UpdatedAt = now
		if !account.Enabled {
			account.Status = StatusDisabled
		} else if account.Status == StatusDisabled {
			account.Status = StatusActive
		}
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	s.markDirtyLocked()
	return updated, nil
}

// SaveAccountState persists mutable runtime fields of one account.
func (s *Store) SaveAccountState(id string, apply func(*Account)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.state.Accounts {
		if account.ID == id {
			apply(account)
			s.markDirtyLocked()
			return
		}
	}
	// An unknown id changes nothing, so it must not schedule a write either.
}

func (s *Store) AccountGroups() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	for _, account := range s.state.Accounts {
		if account.Group == "" {
			continue
		}
		if _, ok := seen[account.Group]; ok {
			continue
		}
		seen[account.Group] = struct{}{}
		out = append(out, account.Group)
	}
	sort.Strings(out)
	return out
}

// --------------------------------------------------------------- client keys

// clone returns a detached copy of a client key.
//
// The store owns the live keys and mutates them in place under s.mu, so every
// pointer handed out must be a copy; ClientKey holds only value types, which
// makes a plain struct copy a deep copy.
func (k *ClientKey) clone() *ClientKey {
	if k == nil {
		return nil
	}
	out := *k
	return &out
}

func (s *Store) ListClientKeys() []*ClientKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ClientKey, len(s.state.ClientKeys))
	for index, key := range s.state.ClientKeys {
		out[index] = key.clone()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) ClientKeyByValue(value string) (*ClientKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.state.ClientKeys {
		if key.Key == value {
			return key.clone(), true
		}
	}
	return nil, false
}

func (s *Store) CreateClientKey(name string, rpm, maxConcurrent int) (*ClientKey, error) {
	s.mu.Lock()
	defer s.unlockAndNotify()
	key := &ClientKey{
		ID:            "key_" + randomToken(6),
		Name:          name,
		Key:           "sk-mm-" + randomToken(20),
		Enabled:       true,
		RPMLimit:      rpm,
		MaxConcurrent: maxConcurrent,
		CreatedAt:     time.Now(),
	}
	s.state.ClientKeys = append(s.state.ClientKeys, key)
	s.markDirtyLocked()
	// Hand back a copy so the caller cannot race with BumpClientKeyUsage.
	return key.clone(), nil
}

func (s *Store) UpdateClientKey(id string, apply func(*ClientKey)) (*ClientKey, error) {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for _, key := range s.state.ClientKeys {
		if key.ID != id {
			continue
		}
		apply(key)
		s.markDirtyLocked()
		return key.clone(), nil
	}
	return nil, ErrNotFound
}

func (s *Store) DeleteClientKey(id string) error {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for index, key := range s.state.ClientKeys {
		if key.ID != id {
			continue
		}
		s.state.ClientKeys = append(s.state.ClientKeys[:index], s.state.ClientKeys[index+1:]...)
		s.markDirtyLocked()
		return nil
	}
	return ErrNotFound
}

// BumpClientKeyUsage records usage without forcing a synchronous disk write on
// the request path. The change is still queued for the debounced background
// write — markDirtyLocked never blocks — so counters survive a crash instead of
// silently rewinding to whatever flush last happened to follow them.
func (s *Store) BumpClientKeyUsage(id string) {
	s.mu.Lock()
	for _, key := range s.state.ClientKeys {
		if key.ID == id {
			key.TotalRequests++
			key.LastUsedAt = time.Now()
			s.markDirtyLocked()
			break
		}
	}
	s.mu.Unlock()
}

// -------------------------------------------------------------------- models

// clone returns a detached copy of a model entry.
//
// The four generation-option fields are slices, so a plain struct copy would
// leave the copy sharing its backing arrays with the store's own entry: a
// caller writing through the copy would scribble over the live catalogue
// without holding the lock. Each slice is copied; a nil source stays nil,
// which the merge and the gateway read as "unconstrained".
func (m *ModelConfig) clone() *ModelConfig {
	if m == nil {
		return nil
	}
	out := *m
	out.Ratios = append([]string(nil), m.Ratios...)
	out.Resolutions = append([]string(nil), m.Resolutions...)
	out.Durations = append([]int(nil), m.Durations...)
	out.ContextWindows = append([]int(nil), m.ContextWindows...)
	return &out
}

func (s *Store) ListModels() []*ModelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ModelConfig, len(s.state.Models))
	for index, model := range s.state.Models {
		out[index] = model.clone()
	}
	return out
}

func (s *Store) ModelByID(id string) (*ModelConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, model := range s.state.Models {
		if model.ID == id {
			// A detached snapshot: RecordModelUsage mutates the live entry's
			// counters while gateway requests hold this value for their whole
			// duration.
			return model.clone(), true
		}
	}
	return nil, false
}

func (s *Store) UpdateModel(id string, apply func(*ModelConfig)) (*ModelConfig, error) {
	s.mu.Lock()
	defer s.unlockAndNotify()
	for _, model := range s.state.Models {
		if model.ID != id {
			continue
		}
		apply(model)
		s.markDirtyLocked()
		// A detached snapshot, like ListModels hands out.
		return model.clone(), nil
	}
	return nil, ErrNotFound
}

// RecordModelUsage accumulates per-model counters. Like BumpClientKeyUsage it
// queues a debounced write rather than touching the disk on the request path.
func (s *Store) RecordModelUsage(id string, requests, tokens int64) {
	s.mu.Lock()
	for _, model := range s.state.Models {
		if model.ID == id {
			model.Requests += requests
			model.Tokens += tokens
			s.markDirtyLocked()
			break
		}
	}
	s.mu.Unlock()
}

// -------------------------------------------------------------------- audits

func (s *Store) AppendAudit(audit *Audit) {
	settings := s.Settings()
	s.mu.Lock()
	s.state.Audits = append([]*Audit{audit}, s.state.Audits...)
	if len(s.state.Audits) > settings.Audit.MaxRecords {
		s.state.Audits = s.state.Audits[:settings.Audit.MaxRecords]
	}
	// The record must reach the disk: without a write queued here a crash
	// loses every audit since the last unrelated flush.
	s.markDirtyLocked()
	s.mu.Unlock()
}

func (s *Store) ListAudits() []*Audit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Audit, len(s.state.Audits))
	for index, audit := range s.state.Audits {
		copied := *audit
		out[index] = &copied
	}
	return out
}

func (s *Store) AuditByID(id string) (*Audit, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, audit := range s.state.Audits {
		if audit.ID == id {
			copied := *audit
			return &copied, true
		}
	}
	return nil, false
}

func (s *Store) ClearAudits() error {
	s.mu.Lock()
	defer s.unlockAndNotify()
	s.state.Audits = nil
	s.markDirtyLocked()
	return nil
}

// PurgeAudits drops records older than the retention window.
func (s *Store) PurgeAudits() {
	settings := s.Settings()
	if settings.Audit.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().Add(-settings.Retention())
	s.mu.Lock()
	kept := make([]*Audit, 0, len(s.state.Audits))
	for _, audit := range s.state.Audits {
		if audit.CreatedAt.After(cutoff) {
			kept = append(kept, audit)
		}
	}
	if len(kept) != len(s.state.Audits) {
		s.state.Audits = kept
		// The drop has to reach the disk: a purge that only edited memory
		// resurrects the records on the next restart, because the file still
		// describes them.
		s.markDirtyLocked()
	}
	s.mu.Unlock()
}

// --------------------------------------------------------------------- media

func (s *Store) AddMedia(item *MediaItem) {
	s.mu.Lock()
	s.state.Media = append([]*MediaItem{item}, s.state.Media...)
	if len(s.state.Media) > 500 {
		s.state.Media = s.state.Media[:500]
	}
	// Queue the write so a finished generation is not forgotten by a crash.
	s.markDirtyLocked()
	s.mu.Unlock()
}

func (s *Store) ListMedia() []*MediaItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*MediaItem, len(s.state.Media))
	for index, item := range s.state.Media {
		copied := *item
		out[index] = &copied
	}
	return out
}
