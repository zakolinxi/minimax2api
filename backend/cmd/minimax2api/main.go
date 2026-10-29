package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"minimax2api/internal/admin"
	"minimax2api/internal/config"
	"minimax2api/internal/gateway"
	"minimax2api/internal/minimax"
	"minimax2api/internal/pool"
	"minimax2api/internal/signin"
	"minimax2api/internal/store"
)

func main() {
	cfg := config.Load()

	st, err := store.Open(cfg.DataDir, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		log.Fatalf("初始化数据存储失败: %v", err)
	}

	settingsFn := func() config.Settings { return st.Settings() }
	client := minimax.New(settingsFn)
	accountPool := pool.New(st, settingsFn)
	signinSvc := signin.New(st, client, settingsFn, gateway.CredentialOf)
	api := admin.New(st, accountPool, client, signinSvc, settingsFn, cfg.BrowserLoginBridge)
	compat := gateway.New(st, accountPool, client, settingsFn)

	mux := http.NewServeMux()
	api.Register(mux)

	mux.HandleFunc("GET /health", compat.Health)
	mux.HandleFunc("GET /v1/models", compat.Models)
	mux.HandleFunc("POST /v1/chat/completions", compat.ChatCompletions)
	mux.HandleFunc("POST /v1/messages", compat.AnthropicMessages)
	mux.HandleFunc("POST /v1/images/generations", compat.ImageGenerations)
	mux.HandleFunc("POST /v1/videos/generations", compat.VideoGenerations)
	mux.HandleFunc("POST /v1/files", compat.FilesUpload)
	mux.HandleFunc("GET /v1/files", compat.FilesList)
	mux.HandleFunc("GET /v1/files/{id}", compat.FilesRetrieve)
	mux.HandleFunc("GET /v1/files/{id}/content", compat.FilesContent)
	mux.HandleFunc("DELETE /v1/files/{id}", compat.FilesDelete)

	// The media handler reads the directory from settings on every request so a
	// console change takes effect without a restart, and refuses directory
	// requests: a bare http.FileServer answers GET /media/ with a full listing
	// of everything ever generated, which turns an unauthenticated endpoint
	// into an index of the whole gallery.
	mux.HandleFunc("GET /media/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		prefix := "/media/"
		http.StripPrefix(prefix, http.FileServer(http.Dir(st.Settings().Media.GeneratedDir))).ServeHTTP(w, r)
	})

	registerDebug(mux)
	registerStatic(mux, cfg.StaticDir)

	// MaxConcurrentRequests has been a visible setting forever, but nothing
	// ever read it: the console showed a number that did nothing. Wire it as a
	// process-wide gate — without one, N client keys under no per-key limit
	// can drive the memory-backed turn path (64MB bodies, in-memory
	// attachments) into an OOM. Settings are re-read per request, so a console
	// change takes effect without a restart.
	handler := withRequestGate(st, withLogging(withCORS(mux)))
	addr := st.Settings().Server.Addr
	if cfg.Addr != "" {
		addr = cfg.Addr
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go janitor(st)

	// The check-in scheduler and credit poller live for as long as the process
	// does, so they take a context cancelled by the same signal that stops the
	// HTTP server.
	runCtx, stopRun := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRun()
	signinSvc.Start(runCtx)
	// Accounts with a stored login credential refresh their own token before it
	// expires; the loop is a no-op when no browser login bridge is configured.
	api.StartAutoLogin(runCtx)

	go func() {
		log.Printf("MiniMax2API %s 已启动 · 管理台 http://%s · 数据目录 %s", gateway.Version, displayAddr(addr), cfg.DataDir)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务异常: %v", err)
		}
	}()

	<-runCtx.Done()
	stopRun()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("关闭服务时出错: %v", err)
	}
	if err := st.Save(); err != nil {
		log.Printf("保存数据时出错: %v", err)
	}
	log.Println("已退出")
}

// registerDebug exposes pprof endpoints for diagnosing stalls. They are only
// served to loopback clients so a public deployment cannot leak heap contents.
func registerDebug(mux *http.ServeMux) {
	local := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// RemoteAddr for an IPv6 loopback client reads "[::1]:port" —
			// trimming at the last colon leaves the brackets on, and comparing
			// that against "::1" never matched. Parse the address properly.
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /debug/pprof/", local(pprof.Index))
	mux.HandleFunc("GET /debug/pprof/goroutine", local(pprof.Handler("goroutine").ServeHTTP))
	mux.HandleFunc("GET /debug/pprof/heap", local(pprof.Handler("heap").ServeHTTP))
	mux.HandleFunc("GET /debug/pprof/mutex", local(pprof.Handler("mutex").ServeHTTP))
	mux.HandleFunc("GET /debug/pprof/block", local(pprof.Handler("block").ServeHTTP))
}

// registerStatic serves the built frontend and falls back to index.html so
// client-side routes work on refresh.
func registerStatic(mux *http.ServeMux, staticDir string) {
	index := filepath.Join(staticDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		log.Printf("提示: 未找到前端产物 %s，仅提供 API（可先执行 cd frontend && npm run build）", staticDir)
		return
	}

	fileServer := http.FileServer(http.Dir(staticDir))
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		// Never let the shell be cached: it names the hashed bundle, so a stale
		// copy keeps pointing at a JS file that no longer exists after a
		// rebuild. Without an explicit header Chrome falls back to heuristic
		// caching based on Last-Modified and can serve a stale index.html.
		w.Header().Set("cache-control", "no-cache")
		http.ServeFile(w, r, index)
	}

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			serveIndex(w, r)
			return
		}
		// A backslash or a dot-dot segment never names a bundled asset. On
		// Windows a decoded %5C joins outside staticDir, and the stat below
		// then answers "exists" for files the server must never confirm.
		if strings.Contains(path, "\\") || strings.Contains(path, "..") {
			http.NotFound(w, r)
			return
		}
		// API prefixes are registered separately; anything else falls back to
		// the SPA entry point when the file does not exist.
		if _, err := os.Stat(filepath.Join(staticDir, filepath.Clean(strings.TrimPrefix(path, "/")))); err != nil {
			serveIndex(w, r)
			return
		}
		// Vite fingerprints asset filenames, so they can be cached forever.
		if strings.HasPrefix(path, "/assets/") {
			w.Header().Set("cache-control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// janitor purges expired audits in the background.
func janitor(st *store.Store) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		st.PurgeAudits()
	}
}

func displayAddr(addr string) string {
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	return addr
}

// withCORS reflects the caller's origin without credentials.
//
// Authentication is an Authorization header carried by the client, so no
// browser request needs `allow-credentials` — and reflecting any origin WITH
// it (the previous behaviour) is the classic setup where a single cookie-based
// session turns every website into a full-authority admin client. Without
// credentials, reflecting the origin is what lets self-hosted browser clients
// call /v1 with their own key while keeping the admin surface safe by
// construction. Vary: Origin keeps shared caches from handing one origin's
// preflight to another.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("origin")
		if origin != "" {
			w.Header().Set("access-control-allow-origin", origin)
			w.Header().Set("access-control-allow-headers", "authorization,content-type,x-api-key,x-session-id")
			w.Header().Set("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			w.Header().Add("vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withRequestGate caps how many requests the process works on at once. A
// zero or negative setting means unlimited, matching how the per-key limits
// read zero.
func withRequestGate(st *store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := st.Settings().Server.MaxConcurrentRequests
		if limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		gate := semaFor(st, limit)
		select {
		case gate <- struct{}{}:
			// Release through the same gate that admitted this request: a
			// settings change swaps the channel, and draining a slot from the
			// new one would leak the old gate's slot forever.
			defer func() { <-gate }()
			next.ServeHTTP(w, r)
		default:
			// A bounded wait would pile every queued request onto the same
			// goroutine budget the gate exists to protect; an immediate 503
			// with Retry-After is the honest answer at capacity.
			w.Header().Set("retry-after", "1")
			http.Error(w, "服务器繁忙，请稍后重试", http.StatusServiceUnavailable)
			return
		}
	})
}

// semaFor returns the process-wide gate, rebuilding it when the configured
// limit changes. Holders of the previous gate release into it (the handler
// captures the channel), so a swap strands at most the in-flight requests'
// slots in the retired gate until they finish.
var (
	gateMu   sync.Mutex
	gateCap  int
	gateChan chan struct{}
)

func semaFor(st *store.Store, limit int) chan struct{} {
	gateMu.Lock()
	defer gateMu.Unlock()
	if gateChan == nil || gateCap != limit {
		gateChan = make(chan struct{}, limit)
		gateCap = limit
	}
	return gateChan
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/v1") || r.URL.Path == "/health" {
			started := time.Now()
			writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(writer, r)
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, writer.status, time.Since(started).Round(time.Millisecond))
			return
		}
		next.ServeHTTP(w, r)
	})
}
