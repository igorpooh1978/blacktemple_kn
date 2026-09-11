export type Screen = "setup" | "login" | "main" | "advanced";

export type AuthState = {
  initialized: boolean;
  authenticated: boolean;
};

export function screenFromAuthState(state: AuthState): Screen {
  if (!state.initialized) {
    return "setup";
  }
  if (!state.authenticated) {
    return "login";
  }
  return "main";
}

export const SESSION_EXPIRED_MESSAGE = "Сессия истекла. Войдите снова.";

export function importSuccessNotice(serverCount: number): string {
  if (serverCount > 0) {
    return "Получено " + String(serverCount) + " серверов";
  }
  return "Готово";
}

export function importErrorMessage(httpStatus: number): string | "session" {
  switch (httpStatus) {
    case 401:
      return "session";
    case 400:
      return "Ключ или подписка имеют неизвестный формат.";
    case 413:
      return "Подписка слишком большая.";
    case 502:
      return "Не удалось обновить список серверов. Сохранённый рабочий сервер оставлен без изменений.";
    case 504:
      return "Сервер подписки не ответил вовремя.";
    default:
      return "Не удалось добавить ключ";
  }
}

export function screenAfterSetupStatus(
  httpStatus: number,
): "login" | "authenticate" | "stay" {
  if (httpStatus === 409) {
    return "login";
  }
  if (httpStatus === 204) {
    return "authenticate";
  }
  return "stay";
}

export function defaultDisconnectedStatus(): {
  connection: "disconnected";
  routing: "smart";
  serverMode: "auto";
  key: "missing";
} {
  return {
    connection: "disconnected",
    routing: "smart",
    serverMode: "auto",
    key: "missing",
  };
}
