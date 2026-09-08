import { describe, expect, it } from "vitest";
import { App } from "./app";
import { screenAfterSetupStatus } from "./flow";
import {
  connectionLabel,
  keyLabel,
  routingLabel,
  serverLabel,
} from "./labels";

describe("App", () => {
  it("is a function component", () => {
    expect(typeof App).toBe("function");
  });
});

describe("first-run flow", () => {
  it("goes to login on setup 409", () => {
    expect(screenAfterSetupStatus(409)).toBe("login");
  });

  it("authenticates after setup 204", () => {
    expect(screenAfterSetupStatus(204)).toBe("authenticate");
  });
});

describe("Russian labels", () => {
  it("matches the main screen copy", () => {
    expect(connectionLabel("disconnected")).toBe("Отключено");
    expect(keyLabel("missing")).toBe("Не добавлен");
    expect(keyLabel(undefined)).toBe("Не добавлен");
    expect(serverLabel("auto")).toBe("Автоматически");
    expect(routingLabel("smart")).toBe("Умная");
  });
});
