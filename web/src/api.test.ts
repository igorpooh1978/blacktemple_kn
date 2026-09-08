import { afterEach, describe, expect, it, vi } from "vitest";
import {
  parseStatus,
  postConnection,
  postLogin,
  postProfile,
  postSetup,
} from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("API client", () => {
  it("sends credentials include and JSON password on login", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await postLogin("test-pass");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/login");
    expect(init.credentials).toBe("include");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ password: "test-pass" });
  });

  it("posts setup password with credentials include", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await postSetup("abcdefgh");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/setup");
    expect(init.credentials).toBe("include");
    expect(JSON.parse(String(init.body))).toEqual({ password: "abcdefgh" });
  });

  it("posts connect op without claiming a session header beyond cookies", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 501 }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await postConnection("connect");
    expect(res.status).toBe(501);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
    expect(JSON.parse(String(init.body))).toEqual({ op: "connect" });
  });

  it("posts BlackKey once and does not add extra CSRF headers", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    await postProfile("bk_raw", "home");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(init.credentials).toBe("include");
    expect(headers.get("X-CSRF-Token")).toBeNull();
    expect(JSON.parse(String(init.body))).toEqual({
      blackKey: "bk_raw",
      name: "home",
    });
  });
});

describe("parseStatus", () => {
  it("does not invent connected from partial payloads", () => {
    expect(parseStatus({})).toBeNull();
    expect(
      parseStatus({
        connection: "disconnected",
        routing: "smart",
        serverMode: "auto",
        key: "missing",
      })?.connection,
    ).toBe("disconnected");
  });
});
