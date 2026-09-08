import { useEffect, useState } from "preact/hooks";
import type { ConnectionState, Status, VersionInfo } from "./api";
import {
  getStatus,
  getVersion,
  parseStatus,
  parseVersion,
  postConnection,
  postLogin,
  postProfile,
  postSetup,
  readJson,
} from "./api";
import { interpretConnectionPost } from "./connection";
import {
  defaultDisconnectedStatus,
  screenAfterSetupStatus,
  type Screen,
} from "./flow";
import {
  connectionDotClass,
  connectionLabel,
  keyLabel,
  routingLabel,
  serverLabel,
} from "./labels";
import { importBlackKey } from "./redaction";

const SETUP_MIN_LEN = 8;

export function App() {
  const [screen, setScreen] = useState<Screen>("setup");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [status, setStatus] = useState<Status>(defaultDisconnectedStatus());
  const [version, setVersion] = useState<VersionInfo | null>(null);

  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [blackKey, setBlackKey] = useState("");
  const [keyName, setKeyName] = useState("");

  async function loadStatus(): Promise<boolean> {
    const res = await getStatus();
    if (res.status !== 200) {
      return false;
    }
    const parsed = parseStatus(await readJson(res));
    if (parsed) {
      setStatus(parsed);
    }
    return true;
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const ok = await loadStatus();
        if (!cancelled && ok) {
          setScreen("main");
        }
      } catch {
        /* daemon unreachable — stay on first-run */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (screen !== "main" && screen !== "advanced") {
      return;
    }
    const id = setInterval(() => {
      loadStatus().catch(() => {
        /* keep last GET snapshot; never invent connected */
      });
    }, 4000);
    return () => clearInterval(id);
  }, [screen]);

  function resetAuthFields() {
    setPassword("");
    setRepeat("");
  }

  async function onSetup(ev: Event) {
    ev.preventDefault();
    setError("");
    setNotice("");
    if (password.length < SETUP_MIN_LEN) {
      setError("Минимум 8 символов");
      return;
    }
    if (password !== repeat) {
      setError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await postSetup(password);
      const next = screenAfterSetupStatus(res.status);
      if (next === "login") {
        resetAuthFields();
        setScreen("login");
        setNotice("Пароль уже задан. Войдите.");
        return;
      }
      if (next === "authenticate") {
        const loginRes = await postLogin(password);
        resetAuthFields();
        if (loginRes.status === 200) {
          await loadStatus();
          setScreen("main");
          return;
        }
        setScreen("login");
        setError("Пароль сохранён. Войдите.");
        return;
      }
      setError("Не удалось создать пароль");
    } catch {
      setError("Нет связи с устройством");
    } finally {
      setBusy(false);
    }
  }

  async function onLogin(ev: Event) {
    ev.preventDefault();
    setError("");
    setNotice("");
    setBusy(true);
    try {
      const res = await postLogin(password);
      if (res.status === 200) {
        resetAuthFields();
        await loadStatus();
        setScreen("main");
        return;
      }
      if (res.status === 401) {
        setError("Неверный пароль");
        return;
      }
      setError("Не удалось войти");
    } catch {
      setError("Нет связи с устройством");
    } finally {
      setBusy(false);
    }
  }

  async function onConnect() {
    setError("");
    setNotice("");
    const connected = status.connection === "connected";
    const op = connected ? "disconnect" : "connect";
    setBusy(true);
    try {
      const res = await postConnection(op);
      const result = interpretConnectionPost(res.status, status.connection);
      if (result.notice) {
        setNotice(result.notice);
      }
      if (result.refetch) {
        await loadStatus();
      }
    } catch {
      setError("Нет связи с устройством");
    } finally {
      setBusy(false);
    }
  }

  async function onImportKey(ev: Event) {
    ev.preventDefault();
    setError("");
    setNotice("");
    const raw = blackKey.trim();
    if (!raw) {
      setError("Вставьте BlackKey");
      return;
    }
    setBusy(true);
    try {
      const result = await importBlackKey({
        blackKey: raw,
        name: keyName.trim() || undefined,
        request: async (body) => {
          const res = await postProfile(body.blackKey, body.name);
          return { status: res.status };
        },
      });
      setBlackKey(result.nextFieldValue);
      if (result.status === 201) {
        setKeyName("");
        setNotice("Ключ добавлен");
        await loadStatus();
        return;
      }
      if (result.status === 501) {
        setNotice("Импорт ключей ещё не готов");
        return;
      }
      setError("Не удалось добавить ключ");
    } catch {
      setError("Нет связи с устройством");
    } finally {
      setBusy(false);
    }
  }

  async function openAdvanced() {
    setError("");
    setNotice("");
    setScreen("advanced");
    try {
      const res = await getVersion();
      if (res.status === 200) {
        setVersion(parseVersion(await readJson(res)));
      }
      await loadStatus();
    } catch {
      setError("Нет связи с устройством");
    }
  }

  const connection: ConnectionState = status.connection;

  if (screen === "setup") {
    return (
      <main class="shell">
        <h1>BlackTemple KN</h1>
        <p class="lead">Создайте пароль</p>
        <form onSubmit={onSetup}>
          <label>
            Пароль
            <input
              type="password"
              name="password"
              autocomplete="new-password"
              value={password}
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
          </label>
          <label>
            Повторите пароль
            <input
              type="password"
              name="repeat"
              autocomplete="new-password"
              value={repeat}
              onInput={(e) => setRepeat(e.currentTarget.value)}
            />
          </label>
          {error ? <p class="error">{error}</p> : null}
          {notice ? <p class="notice">{notice}</p> : null}
          <button type="submit" disabled={busy}>
            Продолжить
          </button>
        </form>
        <p class="aux">
          <button
            type="button"
            class="linkbtn"
            onClick={() => {
              setError("");
              setNotice("");
              resetAuthFields();
              setScreen("login");
            }}
          >
            Войти
          </button>
        </p>
      </main>
    );
  }

  if (screen === "login") {
    return (
      <main class="shell">
        <h1>BlackTemple KN</h1>
        <p class="lead">Вход</p>
        <form onSubmit={onLogin}>
          <label>
            Пароль
            <input
              type="password"
              name="password"
              autocomplete="current-password"
              value={password}
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
          </label>
          {error ? <p class="error">{error}</p> : null}
          {notice ? <p class="notice">{notice}</p> : null}
          <button type="submit" disabled={busy}>
            Войти
          </button>
        </form>
        <p class="aux">
          <button
            type="button"
            class="linkbtn"
            onClick={() => {
              setError("");
              setNotice("");
              resetAuthFields();
              setScreen("setup");
            }}
          >
            Первый запуск
          </button>
        </p>
      </main>
    );
  }

  if (screen === "advanced") {
    const xray = status.xray;
    const pid =
      xray?.pid === null || xray?.pid === undefined ? "—" : String(xray.pid);
    const restarts =
      xray?.restartCount === undefined ? "—" : String(xray.restartCount);
    return (
      <main class="shell">
        <h1>BlackTemple KN</h1>
        <p class="lead">Дополнительно</p>
        <ul class="facts">
          <li>
            <span>Версия</span>
            <span>{version?.version ?? "—"}</span>
          </li>
          <li>
            <span>Xray</span>
            <span>{xray?.state ?? "—"}</span>
          </li>
          <li>
            <span>PID</span>
            <span>{pid}</span>
          </li>
          <li>
            <span>Перезапусков</span>
            <span>{restarts}</span>
          </li>
        </ul>
        {error ? <p class="error">{error}</p> : null}
        <button
          type="button"
          class="secondary"
          onClick={() => {
            setError("");
            setScreen("main");
          }}
        >
          Назад
        </button>
      </main>
    );
  }

  return (
    <main class="shell">
      <h1>BlackTemple KN</h1>
      <p class="status">
        <span class={connectionDotClass(connection)} />
        {connectionLabel(connection)}
      </p>
      <ul class="facts">
        <li>
          <span>Ключ</span>
          <span>{keyLabel(status.key)}</span>
        </li>
        <li>
          <span>Сервер</span>
          <span>{serverLabel(status.serverMode)}</span>
        </li>
        <li>
          <span>Маршрутизация</span>
          <span>{routingLabel(status.routing)}</span>
        </li>
      </ul>
      {notice ? <p class="notice">{notice}</p> : null}
      {error ? <p class="error">{error}</p> : null}
      <button
        type="button"
        class="connect"
        disabled={busy || connection === "connecting"}
        onClick={onConnect}
      >
        {connection === "connected" ? "ОТКЛЮЧИТЬ" : "ПОДКЛЮЧИТЬ"}
      </button>
      <form class="keyform" onSubmit={onImportKey}>
        <label>
          BlackKey
          <input
            type="password"
            name="blackKey"
            autocomplete="off"
            value={blackKey}
            onInput={(e) => setBlackKey(e.currentTarget.value)}
          />
        </label>
        <label>
          Имя (необязательно)
          <input
            type="text"
            name="keyName"
            autocomplete="off"
            value={keyName}
            onInput={(e) => setKeyName(e.currentTarget.value)}
          />
        </label>
        <button type="submit" class="secondary" disabled={busy}>
          Добавить ключ
        </button>
      </form>
      <p class="aux">
        <button type="button" class="linkbtn" onClick={openAdvanced}>
          Дополнительно
        </button>
      </p>
    </main>
  );
}
