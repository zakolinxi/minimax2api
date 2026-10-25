const TOKEN_KEY = "minimax2api:admin-token";

export function readToken(): string {
  try {
    return window.localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function writeToken(token: string): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    return;
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number, code = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

type RequestOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  auth?: boolean;
};

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, signal, auth = true } = options;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (auth) {
    const token = readToken();
    if (token) headers.authorization = `Bearer ${token}`;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });

  const text = await response.text();
  const payload = text ? safeParse(text) : null;

  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : "") || `请求失败（HTTP ${response.status}）`;
    const code =
      payload && typeof payload === "object" && "code" in payload
        ? String((payload as { code: unknown }).code)
        : "";
    // A session that expires mid-use should land the operator on the login
    // page instead of surfacing 401 toasts from every query. The login call
    // itself answers 401 for a wrong password — that is a message, not a
    // redirect — and with no stored token there is nothing to clear.
    if (response.status === 401 && path !== "/admin/api/auth/login" && readToken()) {
      writeToken("");
      // Already sitting on the login page (a stale token in storage gets
      // probed on mount): clear it and stay put instead of reloading.
      if (window.location.pathname !== "/login") {
        try {
          // The hard navigation loses react-router's state.from, so carry the
          // current location for the login page to send the operator back to.
          window.sessionStorage.setItem("minimax2api:login-from", window.location.pathname + window.location.search);
        } catch {
          // Storage can be unavailable; the login page falls back to /dashboard.
        }
        window.location.assign("/login");
      }
    }
    throw new ApiError(message, response.status, code);
  }

  return payload as T;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "未知错误";
}
