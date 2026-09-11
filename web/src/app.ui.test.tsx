// @vitest-environment happy-dom

import { afterEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { App } from "./app";
import { VPN_ENGINE_NOT_READY } from "./connection";

const SECRET = "bk_ui_secret_value_do_not_echo";

type StatusBody = {
  connection: "disconnected" | "connecting" | "connected" | "failed";
  routing: "smart" | "all" | "selected";
  serverMode: "auto" | "manual" | "failover" | "rotate";
  key?: "missing" | "active" | "invalid";
  xray?: { state?: string; pid?: number | null; restartCount?: number };
};

let root: HTMLDivElement;

function jsonRes(status: number, body: unknown = null): Response {
  if (body === null) {
    return new Response(null, { status });
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function disconnectedStatus(): StatusBody {
  return {
    connection: "disconnected",
    routing: "smart",
    serverMode: "auto",
    key: "missing",
  };
}

function installFetch(impl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  vi.stubGlobal("fetch", impl);
  window.fetch = impl as typeof fetch;
}

function stubApi(opts: {
  auth?: { initialized: boolean; authenticated: boolean } | null;
  statusCode?: number;
  statusBody?: StatusBody;
  setupStatus?: number;
  loginStatus?: number;
  connectionStatus?: number;
  profileStatus?: number;
  version?: {
    version: string;
    goos: string;
    goarch: string;
    gomips: string;
    cgo: string;
  } | null;
}) {
  const statusBody = opts.statusBody ?? disconnectedStatus();
  const auth = opts.auth ?? { initialized: true, authenticated: true };
  installFetch(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (url.includes("/api/v1/auth/state") && method === "GET") {
      if (opts.auth === null) {
        return jsonRes(404);
      }
      return jsonRes(200, auth);
    }
    if (url.includes("/api/v1/status") && method === "GET") {
      const code = opts.statusCode ?? 200;
      if (code !== 200) {
        return jsonRes(code);
      }
      return jsonRes(200, statusBody);
    }
    if (url.includes("/api/v1/version") && method === "GET") {
      if (!opts.version) {
        return jsonRes(500);
      }
      return jsonRes(200, opts.version);
    }
    if (url.includes("/api/v1/auth/setup") && method === "POST") {
      return jsonRes(opts.setupStatus ?? 204);
    }
    if (url.includes("/api/v1/auth/login") && method === "POST") {
      return jsonRes(opts.loginStatus ?? 200);
    }
    if (url.includes("/api/v1/connection") && method === "POST") {
      return jsonRes(opts.connectionStatus ?? 202);
    }
    if (url.includes("/api/v1/profiles") && method === "POST") {
      return jsonRes(opts.profileStatus ?? 201);
    }
    return jsonRes(404);
  });
}

function mount(): HTMLDivElement {
  root = document.createElement("div");
  document.body.appendChild(root);
  render(<App />, root);
  return root;
}

async function see(text: string): Promise<void> {
  await vi.waitFor(() => {
    expect(root.textContent).toContain(text);
  });
}

function findButton(name: string): HTMLButtonElement {
  const buttons = [...root.querySelectorAll("button")];
  const found = buttons.find((button) => {
    const label = (button.getAttribute("aria-label") ?? "").trim();
    const text = (button.textContent ?? "").replace(/\s+/g, " ").trim();
    return label === name || text === name;
  });
  if (!found) {
    throw new Error(`button "${name}" not found`);
  }
  return found;
}

function typeInto(name: string, value: string): void {
  const input = root.querySelector(`input[name="${name}"]`) as HTMLInputElement;
  if (!input) {
    throw new Error(`input ${name} not found`);
  }
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  setter?.call(input, value);
  const evt = new Event("input", { bubbles: true });
  Object.defineProperty(evt, "target", { configurable: true, value: input });
  Object.defineProperty(evt, "currentTarget", {
    configurable: true,
    value: input,
  });
  input.dispatchEvent(evt);
}

async function openKeyForm(): Promise<void> {
  const summary = root.querySelector("summary") as HTMLElement | null;
  if (!summary) {
    throw new Error("key form summary not found");
  }
  summary.click();
  await vi.waitFor(() => {
    const details = root.querySelector("details") as HTMLDetailsElement | null;
    expect(details?.open).toBe(true);
  });
}

afterEach(() => {
  if (root) {
    render(null, root);
    root.remove();
  }
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("main connection hero", () => {
  it("shows VPN connected only from API status", async () => {
    stubApi({
      statusBody: {
        ...disconnectedStatus(),
        connection: "connected",
        key: "active",
      },
    });
    mount();
    await see("VPN подключён");
    expect(root.textContent).not.toContain("VPN отключён");
    expect(findButton("Отключить")).toBeTruthy();
  });

  it("shows VPN disconnected from API status", async () => {
    stubApi({ statusBody: disconnectedStatus() });
    mount();
    await see("VPN отключён");
    expect(root.textContent).not.toContain("VPN подключён");
    expect(findButton("Подключить").disabled).toBe(false);
  });

  it("does not treat public GET /status as an authenticated session", async () => {
    stubApi({
      auth: null,
      statusBody: disconnectedStatus(),
    });
    mount();
    await see("Первичная настройка");
    expect(root.textContent).not.toContain("VPN отключён");
  });

  it("disables the connect action while connecting", async () => {
    stubApi({
      statusBody: { ...disconnectedStatus(), connection: "connecting" },
    });
    mount();
    await see("Подключение…");
    expect(findButton("Подключение…").disabled).toBe(true);
    expect(root.textContent).not.toContain("VPN подключён");
  });

  it("does not invent connected after a 202 that still reports disconnected", async () => {
    const statusBody = disconnectedStatus();
    stubApi({ statusBody, connectionStatus: 202 });
    mount();
    await see("VPN отключён");
    findButton("Подключить").click();
    await vi.waitFor(() => {
      expect(root.textContent).toContain("VPN отключён");
    });
    expect(root.textContent).not.toContain("VPN подключён");
  });

  it("keeps the UI usable on HTTP 501 connect", async () => {
    stubApi({
      statusBody: disconnectedStatus(),
      connectionStatus: 501,
    });
    mount();
    await see("VPN отключён");
    findButton("Подключить").click();
    await see(VPN_ENGINE_NOT_READY);
    expect(root.textContent).toContain("VPN отключён");
    expect(root.textContent).not.toContain("VPN подключён");
    expect(findButton("Подключить").disabled).toBe(false);
  });
});

describe("BlackKey import", () => {
  it("does not put the secret back into the DOM after a successful import", async () => {
    stubApi({ statusBody: disconnectedStatus(), profileStatus: 201 });
    mount();
    await see("VPN отключён");
    await openKeyForm();
    typeInto("blackKey", SECRET);
    const keyInput = root.querySelector(
      'input[name="blackKey"]',
    ) as HTMLInputElement;
    expect(keyInput.value).toBe(SECRET);
    const form = root.querySelector("form.key-form") as HTMLFormElement;
    form.requestSubmit();
    await see("Готово");
    expect(root.innerHTML).not.toContain(SECRET);
    const later = root.querySelector(
      'input[name="blackKey"]',
    ) as HTMLInputElement | null;
    if (later) {
      expect(later.value).toBe("");
      expect(later.type).toBe("password");
    }
  });

  it("shows an error when adding an empty key", async () => {
    stubApi({ statusBody: disconnectedStatus() });
    mount();
    await see("Не настроен");
    await openKeyForm();
    findButton("Добавить ключ").click();
    await see("Вставьте BlackKey");
  });

  it("treats 401 import as a session expiry not a key error", async () => {
    stubApi({
      statusBody: disconnectedStatus(),
      profileStatus: 401,
    });
    mount();
    await see("VPN отключён");
    await openKeyForm();
    typeInto("blackKey", SECRET);
    const form = root.querySelector("form.key-form") as HTMLFormElement;
    form.requestSubmit();
    await see("Сессия истекла. Войдите снова.");
    expect(root.textContent).toContain("Вход");
    expect(root.textContent).not.toContain("Не удалось добавить ключ");
    expect(root.innerHTML).not.toContain(SECRET);
  });
});

describe("setup and login", () => {
  it("stays on setup when the panel is not initialized and validates the password", async () => {
    stubApi({ auth: { initialized: false, authenticated: false } });
    mount();
    await see("Первичная настройка");
    findButton("Создать пароль").click();
    await see("Минимум 8 символов");
  });

  it("opens login and shows the existing 401 error", async () => {
    stubApi({
      auth: { initialized: true, authenticated: false },
      loginStatus: 401,
    });
    mount();
    await see("Вход");
    typeInto("password", "wrong-pass");
    findButton("Войти").click();
    await see("Неверный пароль");
  });
});

describe("advanced screen", () => {
  it("opens system details and returns to the main screen", async () => {
    stubApi({
      statusBody: {
        ...disconnectedStatus(),
        xray: { state: "RUNNING", pid: 4242, restartCount: 2 },
      },
      version: {
        version: "0.1.0-dev",
        goos: "linux",
        goarch: "mipsle",
        gomips: "softfloat",
        cgo: "0",
      },
    });
    mount();
    await see("VPN отключён");
    findButton("Дополнительно").click();
    await see("Версия");
    await see("0.1.0-dev");
    await see("RUNNING");
    await see("4242");
    findButton("Назад").click();
    await see("VPN отключён");
    expect(root.textContent).toContain("Подключить");
  });
});
