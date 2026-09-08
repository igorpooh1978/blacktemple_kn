import type {
  ConnectionState,
  KeyState,
  RoutingMode,
  ServerMode,
} from "./api";

export function connectionLabel(v: ConnectionState): string {
  switch (v) {
    case "disconnected":
      return "Отключено";
    case "connecting":
      return "Подключение…";
    case "connected":
      return "Подключено";
    case "failed":
      return "Ошибка";
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
      return "Не добавлен";
    case "active":
      return "Добавлен";
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
      return "Умная";
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

export function connectionDotClass(v: ConnectionState): string {
  switch (v) {
    case "disconnected":
      return "dot";
    case "connecting":
      return "dot dot-wait";
    case "connected":
      return "dot dot-on";
    case "failed":
      return "dot dot-fail";
    default: {
      const _never: never = v;
      return _never;
    }
  }
}
