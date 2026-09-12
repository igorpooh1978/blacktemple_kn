export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "failed";

export type RoutingMode = "smart" | "all" | "selected";

export type ServerMode = "auto" | "manual" | "failover" | "rotate";

export type KeyState = "missing" | "active" | "invalid";

export type XrayState =
  | "STOPPED"
  | "STARTING"
  | "RUNNING"
  | "RELOADING"
  | "FAILED"
  | "BACKOFF";

export type XrayProcess = {
  state?: XrayState;
  pid?: number | null;
  version?: string;
  restartCount?: number;
};

export type ConnectionErrorClass =
  | "INVALID_VLESS_USER_ID"
  | "INVALID_REALITY_PUBLIC_KEY"
  | "INVALID_REALITY_SHORT_ID"
  | "XRAY_CONFIG_REJECTED";

export type Status = {
  connection: ConnectionState;
  country?: string;
  latencyMs?: number | null;
  routing: RoutingMode;
  serverMode: ServerMode;
  key?: KeyState;
  geodata?: string;
  errorClass?: ConnectionErrorClass;
  xray?: XrayProcess;
};

export type VersionInfo = {
  version: string;
  goos: string;
  goarch: string;
  gomips: string;
  cgo: string;
};

export type ConnectionOp = "connect" | "disconnect";

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (init?.body != null && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });
}

export async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function isConnectionState(v: unknown): v is ConnectionState {
  return (
    v === "disconnected" ||
    v === "connecting" ||
    v === "connected" ||
    v === "failed"
  );
}

function isRoutingMode(v: unknown): v is RoutingMode {
  return v === "smart" || v === "all" || v === "selected";
}

function isServerMode(v: unknown): v is ServerMode {
  return (
    v === "auto" || v === "manual" || v === "failover" || v === "rotate"
  );
}

function isConnectionErrorClass(v: unknown): v is ConnectionErrorClass {
  return (
    v === "INVALID_VLESS_USER_ID" ||
    v === "INVALID_REALITY_PUBLIC_KEY" ||
    v === "INVALID_REALITY_SHORT_ID" ||
    v === "XRAY_CONFIG_REJECTED"
  );
}

function isKeyState(v: unknown): v is KeyState {
  return v === "missing" || v === "active" || v === "invalid";
}

function isXrayState(v: unknown): v is XrayState {
  return (
    v === "STOPPED" ||
    v === "STARTING" ||
    v === "RUNNING" ||
    v === "RELOADING" ||
    v === "FAILED" ||
    v === "BACKOFF"
  );
}

export function parseStatus(data: unknown): Status | null {
  if (data === null || typeof data !== "object") {
    return null;
  }
  const o = data as Record<string, unknown>;
  if (
    !isConnectionState(o.connection) ||
    !isRoutingMode(o.routing) ||
    !isServerMode(o.serverMode)
  ) {
    return null;
  }
  const status: Status = {
    connection: o.connection,
    routing: o.routing,
    serverMode: o.serverMode,
  };
  if (typeof o.country === "string") {
    status.country = o.country;
  }
  if (o.latencyMs === null || typeof o.latencyMs === "number") {
    status.latencyMs = o.latencyMs;
  }
  if (isKeyState(o.key)) {
    status.key = o.key;
  }
  if (typeof o.geodata === "string") {
    status.geodata = o.geodata;
  }
  if (isConnectionErrorClass(o.errorClass)) {
    status.errorClass = o.errorClass;
  }
  if (o.xray !== null && typeof o.xray === "object") {
    const x = o.xray as Record<string, unknown>;
    const proc: XrayProcess = {};
    if (isXrayState(x.state)) {
      proc.state = x.state;
    }
    if (x.pid === null || typeof x.pid === "number") {
      proc.pid = x.pid;
    }
    if (typeof x.version === "string") {
      proc.version = x.version;
    }
    if (typeof x.restartCount === "number") {
      proc.restartCount = x.restartCount;
    }
    status.xray = proc;
  }
  return status;
}

export function parseVersion(data: unknown): VersionInfo | null {
  if (data === null || typeof data !== "object") {
    return null;
  }
  const o = data as Record<string, unknown>;
  if (
    typeof o.version !== "string" ||
    typeof o.goos !== "string" ||
    typeof o.goarch !== "string" ||
    typeof o.gomips !== "string" ||
    typeof o.cgo !== "string"
  ) {
    return null;
  }
  return {
    version: o.version,
    goos: o.goos,
    goarch: o.goarch,
    gomips: o.gomips,
    cgo: o.cgo,
  };
}

export function getHealth(): Promise<Response> {
  return apiFetch("/health");
}

export function getStatus(): Promise<Response> {
  return apiFetch("/api/v1/status");
}

export function getAuthState(): Promise<Response> {
  return apiFetch("/api/v1/auth/state");
}

export function parseAuthState(data: unknown): {
  initialized: boolean;
  authenticated: boolean;
} | null {
  if (data === null || typeof data !== "object") {
    return null;
  }
  const o = data as Record<string, unknown>;
  if (typeof o.initialized !== "boolean" || typeof o.authenticated !== "boolean") {
    return null;
  }
  return { initialized: o.initialized, authenticated: o.authenticated };
}

export function getVersion(): Promise<Response> {
  return apiFetch("/api/v1/version");
}

export function postSetup(password: string): Promise<Response> {
  return apiFetch("/api/v1/auth/setup", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function postLogin(password: string): Promise<Response> {
  return apiFetch("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function postChangePassword(
  current: string,
  next: string,
): Promise<Response> {
  return apiFetch("/api/v1/auth/password", {
    method: "POST",
    body: JSON.stringify({ current, new: next }),
  });
}

export function postLogout(): Promise<Response> {
  return apiFetch("/api/v1/auth/logout", {
    method: "POST",
  });
}

export function postConnection(op: ConnectionOp): Promise<Response> {
  return apiFetch("/api/v1/connection", {
    method: "POST",
    body: JSON.stringify({ op }),
  });
}

export function postProfile(
  blackKey: string,
  name?: string,
): Promise<Response> {
  const body: { blackKey: string; name?: string } = { blackKey };
  if (name !== undefined && name !== "") {
    body.name = name;
  }
  return apiFetch("/api/v1/profiles", {
    method: "POST",
    body: JSON.stringify(body),
  });
}
