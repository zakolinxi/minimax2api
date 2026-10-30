#!/usr/bin/env node
/**
 * Browser login bridge for MiniMax Agent.
 *
 * MiniMax Agent (agent.minimax.io / agent.minimaxi.com) has no OAuth polling
 * endpoint: the login product is a JWT that the site keeps in localStorage
 * under the `_token` key. This process starts a *headful* Chrome on a private
 * profile, opens the target site, lets the operator log in by hand, and polls
 * `localStorage._token` over the Chrome DevTools Protocol. Once the token
 * appears it is handed back to the caller.
 *
 * The same session can also sign in by itself: when POST /login carries
 * `email` and `password`, the bridge drives the unified login page
 * (account.minimax.io/unified-login) — fill the identifier, click Continue,
 * fill the password, click Continue — and then reads the token the agent site
 * sets after the redirect. That path exists so an expired pool can recover
 * without an operator, and it degrades to a clear error when the page wants
 * something only a human can do (a missing password to create, a captcha).
 *
 * Zero third-party dependencies: only Node builtins and the global WebSocket
 * (Node 22). The CDP plumbing is inlined on purpose so this file is
 * self-contained and does not import tools/render.mjs.
 *
 * HTTP surface (JSON everywhere), default http://127.0.0.1:8766
 *   GET    /health              -> {ok:true}
 *   POST   /login               -> {sessionId, target, chromePid}  (returns immediately)
 *                                  body: {target?, proxy?, email?, password?}
 *   GET    /login/<sessionId>   -> {status:"pending"|"ok"|"timeout"|"error", ...}
 *   DELETE /login/<sessionId>   -> {cancelled:true}
 *
 * Options:
 *   --port <n>                       listen port (or BRIDGE_PORT)
 *   CHROME_BIN                       chrome executable (else the platform install
 *                                    paths for macOS/Windows/Linux, then google-chrome
 *                                    / chromium / chromium-browser on PATH)
 *   BRIDGE_LOGIN_TTL_SECONDS         login window, default 600
 *   BRIDGE_AUTO_LOGIN_TTL_SECONDS    automated login budget, default 120
 *
 * Usage:
 *   node tools/browser-login-bridge.mjs --port 8766
 */

import http from "node:http";
import net from "node:net";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DEFAULT_TARGET = "https://agent.minimax.io";
const POLL_INTERVAL_MS = 1000;
// How long to wait for Chrome to publish its debugging endpoint before calling
// startup a failure. Chrome normally opens it in well under a second.
const CDP_WAIT_MS = 15000;
const TOKEN_KEY = "_token";

// The account site that owns the login form, per agent deployment. They are
// separate deployments with separate account databases, so the host has to be
// derived from the target the operator picked rather than hardcoded.
const ACCOUNT_ORIGINS = {
  "agent.minimax.io": "https://account.minimax.io",
  "agent.minimaxi.com": "https://account.minimax.cn",
};
const LOGIN_PATH = "/unified-login";
const MAILBOX_DB = (process.env.BRIDGE_MAILBOX_DB || "").trim();
const MAILBOX_SQLITE = (process.env.BRIDGE_MAILBOX_SQLITE || "sqlite3").trim();

// Reads the JWT and the origin it was read from. localStorage is per-origin, so
// the origin tells the caller which site actually produced the token.
const TOKEN_EXPR = `(() => {
  let token = null;
  try { token = localStorage.getItem(${JSON.stringify(TOKEN_KEY)}); } catch (e) { token = null; }
  return {
    token: typeof token === "string" ? token : null,
    origin: (() => { try { return location.origin; } catch (e) { return ""; } })(),
  };
})()`;

// ---------------------------------------------------------------------------
// CLI / env
// ---------------------------------------------------------------------------

function argValue(name) {
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === `--${name}`) return args[i + 1];
    if (args[i].startsWith(`--${name}=`)) return args[i].slice(name.length + 3);
  }
  return undefined;
}

function positiveInt(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

const PORT = positiveInt(argValue("port") ?? process.env.BRIDGE_PORT, 8766);
const HOST = "127.0.0.1";
const TTL_MS = positiveInt(process.env.BRIDGE_LOGIN_TTL_SECONDS, 600) * 1000;
// An automated login either finishes in seconds or is stuck on something a
// human has to clear, so it gets a much shorter budget than the manual window.
const AUTO_TTL_MS = positiveInt(process.env.BRIDGE_AUTO_LOGIN_TTL_SECONDS, 120) * 1000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {Map<string, object>} sessionId -> session */
const sessions = new Map();
/** Live Chrome child processes, for cleanup on shutdown. */
const children = new Set();

// Persistent Chrome profile shared by every /login. Keeping it on disk means a
// user who logged in once is still logged in on the next browser-login request,
// so the bridge can grab the token immediately instead of asking them to log in
// again. Never deleted.
const PROFILE_DIR = path.join(os.tmpdir(), "minimax-login-profile");
// Chrome allows only one instance per profile: a second one is redirected to
// the running instance and exits at once. profileChrome records whichever
// process currently owns PROFILE_DIR (or the PROFILE_RESERVED placeholder while
// one is still starting) so a concurrent /login is rejected instead of racing.
const PROFILE_RESERVED = Symbol("profile-reserved");
let profileChrome = null;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Chrome discovery / process control
// ---------------------------------------------------------------------------

function which(cmd) {
  const dirs = (process.env.PATH || "").split(path.delimiter);
  for (const dir of dirs) {
    if (!dir) continue;
    const full = path.join(dir, cmd);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      return full;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

// isExecutable reports whether an absolute candidate path points at something
// we can actually run. Used for the platform install paths below, which are not
// on PATH and so cannot go through which().
function isExecutable(candidate) {
  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

// expandEnv expands a Windows-style "%VAR%\rest" path against process.env.
// Node already receives environment variables with %VAR% unexpanded (unlike the
// shell, which would expand $VAR), so this is the only form we need to handle.
function expandEnv(candidate) {
  if (!candidate.includes("%")) return candidate;
  return candidate.replace(/%([^%]+)%/g, (whole, name) => {
    const value = process.env[name];
    return typeof value === "string" && value ? value : whole;
  });
}

// chromeCandidates returns the well-known install locations for the current
// platform. These are absolute paths because Chrome/Chromium/Edge are not
// normally on PATH on macOS or Windows. Empty/undefined entries (e.g. an
// unset %PROGRAMFILES%) are dropped by the caller.
function chromeCandidates() {
  if (process.platform === "darwin") {
    return [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
  }
  if (process.platform === "win32") {
    return [
      "%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
      "%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
      "%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe",
      "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe",
    ];
  }
  // Linux: absolute paths that are sometimes not on PATH (e.g. minimal
  // containers, snap-only installs). PATH lookup still runs afterwards.
  return ["/usr/bin/google-chrome", "/usr/bin/chromium", "/snap/bin/chromium"];
}

// findChrome prefers CHROME_BIN, then the platform install paths, then the
// common PATH names. A CHROME_BIN that does not resolve falls through to the
// rest of the chain rather than aborting, so a stale value cannot hide a
// perfectly good Chrome that is otherwise discoverable. Returns null when
// nothing usable is found so the caller can answer with a clear error.
function findChrome() {
  const fromEnv = process.env.CHROME_BIN;
  if (fromEnv) {
    if (path.isAbsolute(fromEnv) || fromEnv.includes(path.sep)) {
      if (isExecutable(fromEnv)) return fromEnv;
    } else {
      const found = which(fromEnv);
      if (found) return found;
    }
  }
  for (const raw of chromeCandidates()) {
    const candidate = expandEnv(raw);
    // A %VAR% that did not expand (variable unset) would otherwise be probed
    // as a literal relative path; skip those.
    if (!candidate || candidate.includes("%") || !path.isAbsolute(candidate)) continue;
    if (isExecutable(candidate)) return candidate;
  }
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const found = which(name);
    if (found) return found;
  }
  return null;
}

// freePort asks the kernel for an unused port and immediately releases it.
// There is a tiny race before Chrome binds it, which is acceptable here.
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, HOST, () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// spawnChrome resolves once the OS confirms the process started, and rejects if
// the executable cannot be launched. The child leads its own process group so
// the whole Chrome tree (zygote, gpu, crashpad helpers) can be signalled at
// once — those helpers outlive the main process and keep the profile dir busy.
function spawnChrome(bin, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(bin, args, { stdio: "ignore", detached: true });
    const onError = (error) => {
      proc.removeListener("spawn", onSpawn);
      reject(error);
    };
    const onSpawn = () => {
      proc.removeListener("error", onError);
      resolve(proc);
    };
    proc.once("error", onError);
    proc.once("spawn", onSpawn);
  });
}

function signalTree(proc, signal) {
  // Negative pid targets the whole process group. Fall back to the single
  // process if the group is already gone.
  try {
    process.kill(-proc.pid, signal);
    return;
  } catch {
    /* fall through */
  }
  try {
    proc.kill(signal);
  } catch {
    /* already gone */
  }
}

function killChrome(proc) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
  signalTree(proc, "SIGTERM");
  const timer = setTimeout(() => {
    if (proc.exitCode === null && proc.signalCode === null) signalTree(proc, "SIGKILL");
  }, 3000);
  timer.unref?.();
  proc.once("exit", () => {
    clearTimeout(timer);
    children.delete(proc);
  });
}

// ---------------------------------------------------------------------------
// Minimal CDP client (inlined; see tools/render.mjs for the same shape)
// ---------------------------------------------------------------------------

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 5000 }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("request timeout")));
    req.on("error", reject);
  });
}

async function waitForCdp(debugPort, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const info = await httpGetJson(`http://${HOST}:${debugPort}/json/version`);
      if (info && info.webSocketDebuggerUrl) return true;
    } catch {
      /* not up yet */
    }
    await sleep(200);
  }
  return false;
}

function attach(wsUrl) {
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WebSocket(wsUrl);
    } catch (error) {
      reject(error);
      return;
    }
    const openTimer = setTimeout(() => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      reject(new Error("websocket open timeout"));
    }, 10000);

    ws.addEventListener(
      "open",
      () => {
        clearTimeout(openTimer);
        let nextId = 0;
        let closed = false;
        const pending = new Map();

        ws.addEventListener("message", (event) => {
          let msg;
          try {
            msg = JSON.parse(event.data);
          } catch {
            return;
          }
          if (msg.id !== undefined && pending.has(msg.id)) {
            const { resolve: res, reject: rej } = pending.get(msg.id);
            pending.delete(msg.id);
            if (msg.error) rej(new Error(JSON.stringify(msg.error)));
            else res(msg.result);
          }
        });
        ws.addEventListener("close", () => {
          closed = true;
          for (const { reject: rej } of pending.values()) rej(new Error("websocket closed"));
          pending.clear();
        });
        ws.addEventListener("error", () => {
          /* a close event follows; handled above */
        });

        resolve({
          get closed() {
            return closed;
          },
          send(method, params = {}) {
            const id = (nextId += 1);
            return new Promise((res, rej) => {
              if (closed) {
                rej(new Error("websocket closed"));
                return;
              }
              pending.set(id, { resolve: res, reject: rej });
              ws.send(JSON.stringify({ id, method, params }));
            });
          },
          close() {
            try {
              ws.close();
            } catch {
              /* ignore */
            }
          },
        });
      },
      { once: true },
    );

    ws.addEventListener(
      "error",
      () => {
        clearTimeout(openTimer);
        reject(new Error("websocket failed"));
      },
      { once: true },
    );
  });
}

async function evaluate(cdp, expression) {
  const { result, exceptionDetails } = await cdp.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (exceptionDetails) {
    throw new Error(
      exceptionDetails.exception?.description || exceptionDetails.text || "evaluate failed",
    );
  }
  return result.value;
}

// connectCdp re-reads the target list and attaches to the current active page.
// Called on first use and again whenever the previous WebSocket died (a login
// redirect can invalidate it), so navigation does not stop the poll loop.
async function connectCdp(debugPort, origin) {
  let targets;
  try {
    targets = await httpGetJson(`http://${HOST}:${debugPort}/json`);
  } catch {
    return null;
  }
  if (!Array.isArray(targets)) return null;
  const pages = targets.filter((t) => t.type === "page" && t.webSocketDebuggerUrl);
  if (!pages.length) return null;
  const preferred = pages.find((t) => typeof t.url === "string" && t.url.startsWith(origin)) || pages[0];
  try {
    return await attach(preferred.webSocketDebuggerUrl);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Automated sign-in
// ---------------------------------------------------------------------------

/** The login form's home for one agent deployment. */
function accountOriginFor(target) {
  try {
    return ACCOUNT_ORIGINS[new URL(target).hostname] || ACCOUNT_ORIGINS["agent.minimax.io"];
  } catch {
    return ACCOUNT_ORIGINS["agent.minimax.io"];
  }
}

const IDENTIFIER_SELECTOR =
  'input[type="email"], input[type="tel"], input[name*="email" i], input[name*="phone" i]';

const PAGE_STATE_EXPR = `(() => ({
  url: location.href,
  origin: (() => { try { return location.origin; } catch (e) { return ""; } })(),
  hasIdentifier: !!document.querySelector(${JSON.stringify(IDENTIFIER_SELECTOR)}),
  hasPassword: !!document.querySelector('input[type="password"]'),
  text: (document.body && document.body.innerText ? document.body.innerText : "").slice(0, 300),
  token: (() => { try { return localStorage.getItem(${JSON.stringify(TOKEN_KEY)}); } catch (e) { return null; } })(),
}))()`;

// React owns these inputs and ignores a plain `.value =` assignment, so the
// value goes in through the prototype setter and then announces itself as a
// real edit. Same trick the site's own autofill produces.
function fillExpr(selector, value) {
  return `(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    el.focus();
    setter.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  })()`;
}

// The page says Continue (or 继续/下一步 on the mainland site). Falling back to
// a form submit keeps the driver working if the button is rendered as a link.
const CLICK_CONTINUE_EXPR = `(() => {
  const labels = ["Continue", "continue", "继续", "下一步", "Next"];
  const buttons = Array.from(document.querySelectorAll('button, [role="button"]'));
  const hit = buttons.find((b) => {
    const text = (b.textContent || "").trim();
    return text && labels.some((label) => text.startsWith(label)) && !b.disabled;
  });
  if (hit) { hit.click(); return true; }
  const form = document.querySelector("form");
  if (form) { form.requestSubmit(); return true; }
  return false;
})()`;

// The unified login form refuses to advance until the terms checkbox above the
// legal text is ticked. It renders as a bare <button> next to the "I have read
// and agree" paragraph with no role or aria state, so the driver clicks it once
// per fresh render before pressing Continue.
const CLICK_TERMS_EXPR = `(() => {
  const p = Array.from(document.querySelectorAll("p")).find((el) => {
    const text = (el.textContent || "").trim();
    return (text.includes("I have read and agree") || text.includes("同意")) && el.parentElement && el.parentElement.querySelector("button");
  });
  if (!p) return false;
  p.parentElement.querySelector("button").click();
  return true;
})()`;

// The agent site's Sign in button is the only door that hands the account
// site a login_redirect (oauth2 authorize + callback). Without it the login
// succeeds but the exchange that produces the agent token never happens.
const CLICK_SIGN_IN_EXPR = `(() => {
  const b = Array.from(document.querySelectorAll('button, a, [role="button"]')).find((x) => {
    const text = (x.textContent || "").trim();
    return text === "Sign in" || text === "登录";
  });
  if (!b) return false;
  b.click();
  return true;
})()`;

// --- Email-code sign-in ------------------------------------------------------

// The mailbox is a plain SQLite database fed by the deployment's mail sink;
// asking it through the sqlite3 CLI keeps this file dependency-free.
function mailboxCode(email, sinceEpoch) {
  const [local, domain] = String(email || "").split("@");
  if (!local || !domain) return null;
  const esc = (v) => v.replace(/'/g, "''");
  try {
    const out = execFileSync(
      MAILBOX_SQLITE,
      [
        MAILBOX_DB,
        `SELECT code FROM messages WHERE lower(local)=lower('${esc(local)}') AND lower(domain)=lower('${esc(domain)}') AND code IS NOT NULL AND created > ${Math.floor(sinceEpoch)} ORDER BY created DESC LIMIT 1;`,
      ],
      { encoding: "utf-8", timeout: 8000 },
    ).trim();
    return out || null;
  } catch {
    return null;
  }
}

async function buttonPoint(cdp, label) {
  const quoted = JSON.stringify(label);
  return evaluate(cdp, `(() => {
    const b = Array.from(document.querySelectorAll("button")).find((x) => (x.textContent || "").trim() === ${quoted});
    if (!b) return null;
    const r = b.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return null;
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  })()`);
}

async function clickPoint(cdp, point) {
  await cdp.send("Input.dispatchMouseEvent", {
    type: "mousePressed",
    x: point.x,
    y: point.y,
    button: "left",
    clickCount: 1,
  });
  await cdp.send("Input.dispatchMouseEvent", {
    type: "mouseReleased",
    x: point.x,
    y: point.y,
    button: "left",
    clickCount: 1,
  });
}

async function codeInputPoint(cdp) {
  return evaluate(cdp, `(() => {
    const el = Array.from(document.querySelectorAll("input")).find((x) =>
      x.type !== "hidden" && x.type !== "password" && x.type !== "email" &&
      x.offsetParent !== null && x.getBoundingClientRect().width > 0);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  })()`);
}

// Signs in with the emailed one-time code. Returns "" on success (the token
// poll loop owns the finish line) or a human-readable failure.
async function emailCodeLogin(session, email) {
  const cdp = session.cdp;
  if (!cdp) return "code sign-in: browser connection lost";
  if (!email) return "code sign-in: the account has no email";
  if (!MAILBOX_DB) return "code sign-in: BRIDGE_MAILBOX_DB is not configured";
  const deadline = Math.min(session.deadline, Date.now() + AUTO_TTL_MS);
  // Codes live five minutes upstream, so a slightly older one is still usable.
  const since = Math.floor(Date.now() / 1000) - 300;

  let input = await codeInputPoint(cdp);
  if (!input) {
    const option = await buttonPoint(cdp, "Use email verification code");
    if (!option) return "code sign-in: the form has no email-code option";
    // The send is captcha-scored and can be refused for a moment; a second
    // click a little later catches windows where the first one loses.
    for (let attempt = 0; attempt < 2 && !input; attempt++) {
      if (session.status !== "pending") return "";
      await clickPoint(cdp, option);
      for (let i = 0; i < 25 && !input; i++) {
        await sleep(1000);
        if (session.status !== "pending") return "";
        input = await codeInputPoint(cdp);
      }
    }
  }
  if (!input) return "code sign-in: the code form never appeared";

  let code = null;
  while (!code && Date.now() < deadline) {
    if (session.status !== "pending") return "";
    code = mailboxCode(email, since);
    if (!code) await sleep(2000);
  }
  if (!code) return "code sign-in: no verification code arrived in the mailbox";

  await clickPoint(cdp, input);
  await sleep(250);
  await cdp.send("Input.insertText", { text: code });
  await sleep(500);
  const submit = await buttonPoint(cdp, "Continue");
  if (!submit) return "code sign-in: no submit button";
  await clickPoint(cdp, submit);

  const agentOrigin = originOf(session.target);
  for (let i = 0; i < 20; i++) {
    await sleep(1000);
    if (session.status !== "pending") return "";
    let origin = "";
    try {
      origin = await evaluate(cdp, "location.origin");
    } catch {
      return "";
    }
    if (origin === agentOrigin) return "";
  }
  // The callback URL carries the oauth code; revisiting the agent site makes
  // the SPA replay it so the token still lands.
  try {
    await cdp.send("Page.navigate", { url: session.target });
  } catch {
    return "code sign-in: could not return to the agent site";
  }
  return "";
}

/**
 * Drives the unified login form with the credentials the session carries.
 *
 * Runs beside the token poll, which owns the success signal: this function only
 * needs to get the page to the agent site and turn a stuck form into an error
 * the caller can show. Every browser step re-checks `session.status` because a
 * human may cancel, or the poll may already have found a token, at any moment.
 */
async function runAutoLogin(session) {
  const agentOrigin = originOf(session.target);
  const credentials = session.credentials;
  const deadline = Math.min(session.deadline, Date.now() + AUTO_TTL_MS);

  const fail = (message) => {
    delete session.credentials;
    if (session.status !== "pending") return;
    session.status = "error";
    session.error = message;
    destroySession(session);
    console.log(`[bridge] ${session.id} auto-login failed: ${message}`);
  };

  const ensureCdp = async () => {
    if (session.cdp && session.cdp.closed) session.cdp = null;
    if (!session.cdp) session.cdp = await connectCdp(session.debugPort, agentOrigin);
    return session.cdp;
  };

  const readPage = async () => {
    if (!(await ensureCdp())) return null;
    try {
      return await evaluate(session.cdp, PAGE_STATE_EXPR);
    } catch {
      // Navigation replaced the execution context; reconnect on the next read.
      try {
        session.cdp.close();
      } catch {
        /* ignore */
      }
      session.cdp = null;
      return null;
    }
  };

  const waitFor = async (predicate, timeoutMs) => {
    const until = Math.min(deadline, Date.now() + timeoutMs);
    while (Date.now() < until) {
      if (session.status !== "pending") return null;
      const state = await readPage();
      if (state && predicate(state)) return state;
      await sleep(500);
    }
    return null;
  };

  try {
    // The profile is shared between logins and may still be signed in as a
    // DIFFERENT account. Both halves of that session have to go before the form
    // is touched: the cookies keep the login page from ever showing, and the
    // agent site's stored token would otherwise be picked up by the poll loop
    // as if this login had produced it — handing the caller the wrong account.
    if (await ensureCdp()) {
      try {
        // Sign out of whatever the profile remembered. Cookies are the session;
        // the account site's own localStorage is left alone so the fingerprint
        // it keeps stable across logins does not churn and look like a new
        // device to the site's risk control.
        await session.cdp.send("Network.clearBrowserCookies");
        // The agent site's `_token` is what the poll loop reads, so it has to
        // go before the form is touched.
        await session.cdp.send("Storage.clearDataForOrigin", {
          origin: agentOrigin,
          storageTypes: "local_storage",
        });
      } catch {
        /* the domains are not always available; the form still works */
      }
      try {
        // The agent site is the entry point: its Sign in button hands the
        // account site the login_redirect (oauth2 authorize + callback) that
        // the token exchange needs; a bare unified-login visit never gets one.
        await session.cdp.send("Page.navigate", { url: session.target });
        await sleep(4000);
        await evaluate(session.cdp, CLICK_SIGN_IN_EXPR);
      } catch {
        /* a dead socket is handled by the wait below */
      }
    }
    // From here on a `_token` can only be one this login produced: the stale
    // copy is already gone, so let the poll loop start believing what it reads.
    session.armed = true;

    const opened = await waitFor(
      (state) => state.origin === agentOrigin || state.hasIdentifier || state.hasPassword,
      20000,
    );
    if (!opened) {
      const last = await readPage();
      return fail(`login page did not render${last && last.text ? `: ${last.text}` : ""}`);
    }
    if (opened.origin === agentOrigin) return; // already signed in; poll loop owns it

    // The login form is client-rendered; events sent before hydration land
    // on nothing, so give the app a beat before touching it.
    await sleep(1500);

    if (!opened.hasPassword) {
      if (!opened.hasIdentifier) return fail(`login page: ${opened.text}`);
      if (!(await evaluate(session.cdp, fillExpr(IDENTIFIER_SELECTOR, credentials.email)))) {
        return fail("login page has no identifier field");
      }
      await evaluate(session.cdp, CLICK_TERMS_EXPR);
      await sleep(300);
      if (!(await evaluate(session.cdp, CLICK_CONTINUE_EXPR))) {
        return fail("login page has no continue button");
      }
    }

    const passwordStep = await waitFor((state) => state.hasPassword, 20000);

    // With a mailbox wired in, the emailed one-time code is the preferred way
    // in: it works for accounts whose password was never set and it never
    // burns a risk-control strike on a stale password.
    if (MAILBOX_DB) {
      const email = (credentials.email || "").trim();
      const codeError = await emailCodeLogin(session, email);
      delete session.credentials;
      if (codeError) return fail(codeError);
      return;
    }

    if (!passwordStep) {
      const last = await readPage();
      // The page falls back to "create a password" (email code) for accounts
      // that never set one, and to a captcha when it does not trust the
      // session. Neither is something this driver can answer.
      return fail(`no password step${last && last.text ? `: ${last.text}` : ""}`);
    }
    if (!(await evaluate(session.cdp, fillExpr('input[type="password"]', credentials.password)))) {
      return fail("password field disappeared");
    }
    if (!(await evaluate(session.cdp, CLICK_CONTINUE_EXPR))) {
      return fail("no continue button on the password step");
    }
    delete session.credentials;

    // The redirect back to the agent site is the finish line. The poll loop
    // picks the token up; this waits only long enough to report a refusal with
    // the page's own words instead of an opaque timeout.
    const landed = await waitFor(
      (state) => state.origin === agentOrigin,
      Math.max(1000, Math.min(30000, deadline - Date.now())),
    );
    if (landed) return;
    const last = await readPage();
    if (last && last.origin === agentOrigin) return;
    return fail(`login did not complete${last && last.text ? `: ${last.text}` : ""}`);
  } catch (error) {
    fail(`auto login crashed: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

function stopPolling(session) {
  if (session.timer) {
    clearTimeout(session.timer);
    session.timer = null;
  }
  if (session.cdp) {
    try {
      session.cdp.close();
    } catch {
      /* ignore */
    }
    session.cdp = null;
  }
}

function destroySession(session) {
  stopPolling(session);
  // Credentials live only as long as the browser session that is using them.
  delete session.credentials;
  const proc = session.chromeProc;
  session.chromeProc = null;
  session.userDataDir = null;
  // The profile is persistent login state, so it is deliberately left on disk
  // for the next /login to reuse. Only the Chrome process is stopped here.
  if (!proc) return;
  killChrome(proc);
}

function expire(session) {
  session.status = "timeout";
  session.error = "login window expired";
  destroySession(session);
  console.log(`[bridge] ${session.id} timeout`);
}

async function runPollLoop(session) {
  const origin = originOf(session.target);
  let ticks = 0;

  const tick = async () => {
    if (session.status !== "pending") return;
    if (Date.now() >= session.deadline) {
      expire(session);
      return;
    }
    ticks += 1;

    let value = null;
    try {
      if (!session.cdp || session.cdp.closed) {
        session.cdp = await connectCdp(session.debugPort, origin);
      }
      if (session.cdp) value = await evaluate(session.cdp, TOKEN_EXPR);
    } catch {
      // A dead socket (navigation / crash) just means reconnect next tick.
      if (session.cdp) {
        try {
          session.cdp.close();
        } catch {
          /* ignore */
        }
      }
      session.cdp = null;
      value = null;
    }

    if (session.status !== "pending") return;

    const token = value && typeof value.token === "string" ? value.token.trim() : "";
    // An automated session starts disarmed: until the driver has cleared the
    // profile's previous session, a token in localStorage belongs to whoever
    // was signed in before, not to the account this login is for.
    if (token && !(session.auto && !session.armed)) {
      session.status = "ok";
      session.token = token;
      session.host = value.origin || origin;
      // The credential has done its job; the session only needs the token now.
      delete session.credentials;
      stopPolling(session);
      // Never log the token itself, only its length.
      console.log(`[bridge] ${session.id} ok host=${session.host} tokenLength=${token.length}`);
      return;
    }

    if (Date.now() >= session.deadline) {
      expire(session);
      return;
    }
    if (ticks % 10 === 0) {
      const left = Math.max(0, Math.round((session.deadline - Date.now()) / 1000));
      console.log(`[bridge] ${session.id} poll pending (${left}s left)`);
    }
    session.timer = setTimeout(tick, POLL_INTERVAL_MS);
  };

  session.timer = setTimeout(tick, 500);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

function sendJson(res, status, obj) {
  if (res.writableEnded) return;
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > limit) {
        req.destroy();
        reject(new Error("request body too large"));
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function handleLogin(req, res) {
  let raw = "";
  try {
    raw = await readBody(req);
  } catch (error) {
    sendJson(res, 400, { error: `cannot read request body: ${error.message}` });
    return;
  }

  let parsed = {};
  if (raw.trim()) {
    try {
      parsed = JSON.parse(raw);
    } catch {
      sendJson(res, 400, { error: "invalid JSON body" });
      return;
    }
  }

  const target =
    typeof parsed.target === "string" && parsed.target.trim() ? parsed.target.trim() : DEFAULT_TARGET;
  let parsedTarget;
  try {
    parsedTarget = new URL(target);
  } catch {
    sendJson(res, 400, { error: "invalid target url" });
    return;
  }
  if (parsedTarget.protocol !== "https:" && parsedTarget.protocol !== "http:") {
    sendJson(res, 400, { error: "target must be an http(s) url" });
    return;
  }

  // Optional outbound proxy for Chrome, e.g. "http://127.0.0.1:7890" or
  // "socks5://127.0.0.1:1080". Passed through verbatim; when empty/absent no
  // --proxy-server flag is added and behaviour is unchanged.
  const proxy =
    (typeof parsed.proxy === "string" && parsed.proxy.trim() ? parsed.proxy : "") ||
    (process.env.BRIDGE_LOGIN_PROXY || "").trim() ||
    "";

  // Credentials turn the session into an automated sign-in. The password is
  // kept in memory only, never logged, and dropped as soon as it is typed.
  const email = typeof parsed.email === "string" || typeof parsed.identifier === "string"
    ? String(parsed.email ?? parsed.identifier).trim()
    : "";
  const password = typeof parsed.password === "string" ? parsed.password : "";
  if ((email && !password) || (!email && password)) {
    sendJson(res, 400, { error: "email and password must be supplied together" });
    return;
  }
  const auto = Boolean(email && password);

  const chrome = findChrome();
  if (!chrome) {
    sendJson(res, 500, {
      error:
        "Chrome not found; set CHROME_BIN or install google-chrome/chromium/chromium-browser on PATH",
    });
    return;
  }

  // One Chrome per profile: reject rather than spawn a second instance that
  // Chrome would silently redirect to the running one and then exit.
  if (profileChrome) {
    sendJson(res, 409, {
      error: "a browser login window is already open; finish or cancel it first",
    });
    return;
  }

  let debugPort;
  try {
    debugPort = await freePort();
  } catch (error) {
    sendJson(res, 500, { error: `could not allocate a debug port: ${error.message}` });
    return;
  }

  // Persistent profile shared across logins (never mkdtemp'd / deleted), so the
  // session survives and the user is not asked to log in every time.
  try {
    fs.mkdirSync(PROFILE_DIR, { recursive: true });
  } catch (error) {
    sendJson(res, 500, { error: `could not create the profile dir: ${error.message}` });
    return;
  }
  const userDataDir = PROFILE_DIR;

  // Automated sessions open the account site's login form; manual ones open the
  // agent site and wait for the operator to sign in there.
  const openUrl = target;

  const args = [
    `--remote-debugging-port=${debugPort}`,
    ...(proxy ? [`--proxy-server=${proxy}`] : []),
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    openUrl,
  ];

  // Reserve the profile synchronously for the whole startup window so a
  // concurrent /login cannot slip a second Chrome in before we have a pid.
  profileChrome = PROFILE_RESERVED;

  let chromeProc;
  try {
    chromeProc = await spawnChrome(chrome, args);
  } catch (error) {
    profileChrome = null;
    sendJson(res, 500, { error: `failed to start Chrome: ${error.message}` });
    return;
  }

  // Hand the reservation over to the real process and release it whenever
  // Chrome exits (cleanup, cancel, timeout, or crash) so the next login can use
  // the profile again.
  profileChrome = chromeProc;
  chromeProc.once("exit", () => {
    if (profileChrome === chromeProc) profileChrome = null;
  });

  children.add(chromeProc);
  chromeProc.once("exit", () => children.delete(chromeProc));

  const up = await waitForCdp(debugPort, CDP_WAIT_MS);
  if (!up) {
    killChrome(chromeProc);
    sendJson(res, 500, { error: "Chrome did not expose a debugging port in time" });
    return;
  }

  const id = globalThis.crypto.randomUUID();
  const session = {
    id,
    target,
    chromePid: chromeProc.pid,
    chromeProc,
    debugPort,
    userDataDir,
    status: "pending",
    token: null,
    host: null,
    error: null,
    cdp: null,
    timer: null,
    auto,
    // Manual sessions are always trustworthy: there is no form driver that has
    // to clean up first. See the poll loop and runAutoLogin.
    armed: !auto,
    credentials: auto ? { email, password } : null,
    createdAt: Date.now(),
    deadline: Date.now() + TTL_MS,
  };
  sessions.set(id, session);

  console.log(
    `[bridge] ${id} started target=${target}${auto ? " auto=1" : ""}${proxy ? ` proxy=${proxy}` : ""} chromePid=${chromeProc.pid} debugPort=${debugPort} ttl=${Math.round(TTL_MS / 1000)}s`,
  );

  runPollLoop(session).catch((error) => {
    if (session.status !== "pending") return;
    session.status = "error";
    session.error = error.message;
    destroySession(session);
    console.log(`[bridge] ${id} error ${error.message}`);
  });
  if (auto) {
    runAutoLogin(session).catch((error) => {
      if (session.status !== "pending") return;
      session.status = "error";
      session.error = error.message;
      destroySession(session);
      console.log(`[bridge] ${id} auto-login error ${error.message}`);
    });
  }

  sendJson(res, 200, { sessionId: id, target, chromePid: chromeProc.pid, auto });
}

function handleGetLogin(res, id) {
  const session = sessions.get(id);
  if (!session) {
    sendJson(res, 404, { error: "unknown session" });
    return;
  }
  switch (session.status) {
    case "pending":
      sendJson(res, 200, { status: "pending" });
      return;
    case "ok":
      sendJson(res, 200, { status: "ok", token: session.token, host: session.host });
      return;
    case "timeout":
      sendJson(res, 200, { status: "timeout", error: session.error || "login window expired" });
      return;
    default:
      sendJson(res, 200, { status: "error", error: session.error || "unknown error" });
  }
}

function handleDeleteLogin(res, id) {
  const session = sessions.get(id);
  if (!session) {
    sendJson(res, 404, { error: "unknown session" });
    return;
  }
  sessions.delete(id);
  session.status = "cancelled";
  destroySession(session);
  console.log(`[bridge] ${id} cancelled`);
  sendJson(res, 200, { cancelled: true });
}

const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${HOST}`);
  } catch {
    sendJson(res, 400, { error: "bad request url" });
    return;
  }
  const method = req.method || "GET";
  const pathname = url.pathname;

  if (pathname === "/health") {
    if (method !== "GET") {
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  if (pathname === "/login") {
    if (method !== "POST") {
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }
    handleLogin(req, res).catch((error) => {
      console.error(`[bridge] /login failed: ${error.message}`);
      sendJson(res, 500, { error: error.message });
    });
    return;
  }

  const match = pathname.match(/^\/login\/([^/]+)$/);
  if (match) {
    const id = decodeURIComponent(match[1]);
    if (method === "GET") {
      handleGetLogin(res, id);
      return;
    }
    if (method === "DELETE") {
      handleDeleteLogin(res, id);
      return;
    }
    sendJson(res, 405, { error: "method not allowed" });
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.on("error", (error) => {
  console.error(`[bridge] server error: ${error.message}`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`[bridge] listening on http://${HOST}:${PORT}`);
  console.log(`[bridge] chrome=${findChrome() || "<not found>"} ttl=${Math.round(TTL_MS / 1000)}s`);
});

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[bridge] ${signal} received, shutting down`);

  const procs = [];
  for (const session of sessions.values()) {
    session.status = "cancelled";
    if (session.timer) clearTimeout(session.timer);
    if (session.cdp) {
      try {
        session.cdp.close();
      } catch {
        /* ignore */
      }
    }
    if (session.chromeProc) procs.push(session.chromeProc);
  }
  sessions.clear();

  // Kill the Chrome processes and wait for them to actually exit (bounded). The
  // persistent profile directory is intentionally kept on disk.
  const exits = procs.map(
    (proc) =>
      new Promise((resolve) => {
        if (proc.exitCode !== null || proc.signalCode !== null) {
          resolve();
          return;
        }
        proc.once("exit", resolve);
        signalTree(proc, "SIGKILL");
      }),
  );
  await Promise.race([Promise.all(exits), sleep(5000)]);

  try {
    server.close();
  } catch {
    /* ignore */
  }
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
