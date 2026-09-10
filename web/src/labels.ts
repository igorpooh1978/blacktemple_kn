import type {
  ConnectionState,
  KeyState,
  RoutingMode,
  ServerMode,
} from "./api";
import { VPN_ENGINE_NOT_READY } from "./connection";

export function connectionLabel(v: ConnectionState): string {
  switch (v) {
    case "disconnected":
      return "VPN отключён";
    case "connecting":
      return "Подключение…";
    case "connected":
      return "VPN подключён";
    case "failed":
      return "Ошибка подключения";
    default: {
      const _never: never = v;
      return _never;
    }
  }
}

export function connectionActionLabel(v: ConnectionState): string {
  switch (v) {
    case "connected":
      return "Отключить";
    case "connecting":
      return "Подключение…";
    case "disconnected":
    case "failed":
      return "Подключить";
    default: {
      const _never: never = v;
      return _never;
    }
  }
}

export function keyLabel(v: KeyState | undefined): string {
  const state: KeyState = v ?? "missing";
  switch (state) {
    case "missing":
      return "Не настроен";
    case "active":
      return "Настроен";
    case "invalid":
      return "Недействителен";
    default: {
      const _never: never = state;
      return _never;
    }
  }
}

export function serverLabel(v: ServerMode): string {
  switch (v) {
    case "auto":
      return "Автоматически";
    case "manual":
      return "Вручную";
    case "failover":
      return "Резервный";
    case "rotate":
      return "Ротация";
    default: {
      const _never: never = v;
      return _never;
    }
  }
}

export function routingLabel(v: RoutingMode): string {
  switch (v) {
    case "smart":
      return "Пока не включена";
    case "all":
      return "Вся";
    case "selected":
      return "Выбранная";
    default: {
      const _never: never = v;
      return _never;
    }
  }
}

export function noticeAlertTone(
  notice: string,
): "info" | "warning" | "success" {
  if (notice === "Ключ добавлен") {
    return "success";
  }
  if (
    notice === VPN_ENGINE_NOT_READY ||
    notice === "Импорт ключей ещё не готов"
  ) {
    return "warning";
  }
  return "info";
}
