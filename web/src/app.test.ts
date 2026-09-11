import { describe, expect, it } from "vitest";
import { App } from "./app";
import {
  importErrorMessage,
  importSuccessNotice,
  screenAfterSetupStatus,
  screenFromAuthState,
  SESSION_EXPIRED_MESSAGE,
} from "./flow";
import {
  connectionActionLabel,
  connectionLabel,
  keyLabel,
  noticeAlertTone,
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

  it("routes setup login and main from auth/state", () => {
    expect(screenFromAuthState({ initialized: false, authenticated: false })).toBe(
      "setup",
    );
    expect(screenFromAuthState({ initialized: true, authenticated: false })).toBe(
      "login",
    );
    expect(screenFromAuthState({ initialized: true, authenticated: true })).toBe(
      "main",
    );
  });

  it("maps 401 import to session expiry not a key error", () => {
    expect(importErrorMessage(401)).toBe("session");
    expect(SESSION_EXPIRED_MESSAGE).toBe("Сессия истекла. Войдите снова.");
    expect(importErrorMessage(400)).toBe(
      "Ключ или подписка имеют неизвестный формат.",
    );
    expect(importErrorMessage(503)).toBe("Резолвер ключа не настроен.");
  });
});

describe("Russian labels", () => {
  it("matches the main screen copy", () => {
    expect(connectionLabel("disconnected")).toBe("VPN отключён");
    expect(connectionLabel("connected")).toBe("VPN подключён");
    expect(connectionLabel("connecting")).toBe("Подключение…");
    expect(keyLabel("missing")).toBe("Не настроен");
    expect(keyLabel("active")).toBe("Настроен");
    expect(keyLabel(undefined)).toBe("Не настроен");
    expect(serverLabel("auto")).toBe("Автоматически");
    expect(routingLabel("smart")).toBe("Пока не включена");
    expect(connectionActionLabel("disconnected")).toBe("Подключить");
    expect(connectionActionLabel("connected")).toBe("Отключить");
    expect(connectionActionLabel("connecting")).toBe("Подключение…");
  });

  it("maps notices to alert tones without exposing secrets", () => {
    expect(noticeAlertTone("Готово")).toBe("success");
    expect(noticeAlertTone(importSuccessNotice(4))).toBe("success");
    expect(importSuccessNotice(4)).toBe("Получено 4 серверов");
    expect(importSuccessNotice(0)).toBe("Готово");
    expect(noticeAlertTone("VPN engine ещё не готов")).toBe("warning");
    expect(noticeAlertTone("Пароль уже задан. Войдите.")).toBe("info");
    expect(noticeAlertTone("Пароль панели изменён.")).toBe("success");
  });
});
