import { useEffect, useState } from "preact/hooks";
import type { ConnectionState, Status, VersionInfo } from "./api";
import {
  getAuthState,
  getStatus,
  getVersion,
  parseAuthState,
  parseStatus,
  parseVersion,
  postConnection,
  postLogin,
  postChangePassword,
  postProfile,
  postSetup,
  readJson,
} from "./api";
import { interpretConnectionPost } from "./connection";
import {
  defaultDisconnectedStatus,
  importErrorMessage,
  screenAfterSetupStatus,
  screenFromAuthState,
  SESSION_EXPIRED_MESSAGE,
  type Screen,
} from "./flow";
import { importBlackKey } from "./redaction";
import { AdvancedScreen } from "./screens/AdvancedScreen";
import { LoginScreen, SetupScreen } from "./screens/AuthScreens";
import { MainScreen } from "./screens/MainScreen";

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
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRepeat, setNewRepeat] = useState("");
  const [blackKey, setBlackKey] = useState("");
  const [keyName, setKeyName] = useState("");

  function expireSession() {
    setBlackKey("");
    setKeyName("");
    setPassword("");
    setRepeat("");
    setCurrentPassword("");
    setNewPassword("");
    setNewRepeat("");
    setStatus(defaultDisconnectedStatus());
    setScreen("login");
    setError(SESSION_EXPIRED_MESSAGE);
    setNotice("");
  }

  async function loadStatus(): Promise<boolean> {
    const res = await getStatus();
    if (res.status === 401) {
      expireSession();
      return false;
    }
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
        const authRes = await getAuthState();
        if (cancelled || authRes.status !== 200) {
          return;
        }
        const state = parseAuthState(await readJson(authRes));
        if (!state || cancelled) {
          return;
        }
        const next = screenFromAuthState(state);
        setScreen(next);
        if (next === "main") {
          await loadStatus();
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
      (async () => {
        try {
          const authRes = await getAuthState();
          if (authRes.status === 200) {
            const state = parseAuthState(await readJson(authRes));
            if (state && !state.authenticated) {
              expireSession();
              return;
            }
          }
          await loadStatus();
        } catch {
          /* keep last GET snapshot; never invent connected */
        }
      })();
    }, 4000);
    return () => clearInterval(id);
  }, [screen]);

  function resetAuthFields() {
    setPassword("");
    setRepeat("");
    setCurrentPassword("");
    setNewPassword("");
    setNewRepeat("");
  }

  async function onSetup(ev: Event) {
    ev.preventDefault();
    setError("");
    setNotice("");
    const form = ev.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const submitted = String(data.get("password") ?? password).trim();
    const submittedRepeat = String(data.get("repeat") ?? repeat).trim();
    if (submitted.length < SETUP_MIN_LEN) {
      setError("Минимум 8 символов");
      return;
    }
    if (submitted !== submittedRepeat) {
      setError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await postSetup(submitted);
      const next = screenAfterSetupStatus(res.status);
      if (next === "login") {
        resetAuthFields();
        setScreen("login");
        setNotice("Пароль уже задан. Войдите.");
        return;
      }
      if (next === "authenticate") {
        const loginRes = await postLogin(submitted);
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
    const form = ev.currentTarget as HTMLFormElement;
    const submitted = String(new FormData(form).get("password") ?? password).trim();
    setBusy(true);
    try {
      const res = await postLogin(submitted);
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
      if (res.status === 401) {
        expireSession();
        return;
      }
      const result = interpretConnectionPost(res.status, status.connection);
      if (res.status === 501) {
        setNotice(result.notice);
      } else if (res.status !== 202) {
        setError(result.notice || "Не удалось изменить подключение");
        if (result.refetch) {
          await loadStatus();
        }
        return;
      }
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
    const form = ev.currentTarget as HTMLFormElement;
    const field = form.querySelector(
      'input[name="blackKey"]',
    ) as HTMLInputElement | null;
    const submitted = String(new FormData(form).get("blackKey") ?? "");
    const raw = (field?.value || submitted || blackKey).trim();
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
      if (result.status === 401) {
        expireSession();
        return;
      }
      if (result.status === 201) {
        setKeyName("");
        setNotice("Готово");
        await loadStatus();
        return;
      }
      if (result.status === 501) {
        setNotice("Импорт ключей ещё не готов");
        return;
      }
      const mapped = importErrorMessage(result.status);
      if (mapped === "session") {
        expireSession();
        return;
      }
      setError(mapped);
    } catch {
      setError("Нет связи с устройством");
    } finally {
      setBusy(false);
    }
  }

  async function onChangePassword(ev: Event) {
    ev.preventDefault();
    setError("");
    setNotice("");
    const form = ev.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const current = String(data.get("currentPassword") ?? currentPassword).trim();
    const next = String(data.get("newPassword") ?? newPassword).trim();
    const repeatVal = String(data.get("newRepeat") ?? newRepeat).trim();
    if (next.length < SETUP_MIN_LEN) {
      setError("Минимум 8 символов");
      return;
    }
    if (next !== repeatVal) {
      setError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await postChangePassword(current, next);
      if (res.status === 401) {
        expireSession();
        return;
      }
      if (res.status === 204) {
        setCurrentPassword("");
        setNewPassword("");
        setNewRepeat("");
        setNotice("Пароль панели изменён.");
        return;
      }
      if (res.status === 403) {
        setError("Неверный текущий пароль");
        return;
      }
      setError("Не удалось сменить пароль");
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
      <SetupScreen
        password={password}
        repeat={repeat}
        busy={busy}
        error={error}
        notice={notice}
        onPassword={setPassword}
        onRepeat={setRepeat}
        onSubmit={onSetup}
        onGoLogin={() => {
          setError("");
          setNotice("");
          resetAuthFields();
          setScreen("login");
        }}
      />
    );
  }

  if (screen === "login") {
    return (
      <LoginScreen
        password={password}
        busy={busy}
        error={error}
        notice={notice}
        onPassword={setPassword}
        onSubmit={onLogin}
      />
    );
  }

  if (screen === "advanced") {
    return (
      <AdvancedScreen
        version={version}
        status={status}
        error={error}
        notice={notice}
        busy={busy}
        currentPassword={currentPassword}
        newPassword={newPassword}
        newRepeat={newRepeat}
        onCurrentPassword={setCurrentPassword}
        onNewPassword={setNewPassword}
        onNewRepeat={setNewRepeat}
        onChangePassword={onChangePassword}
        onBack={() => {
          setError("");
          setNotice("");
          setScreen("main");
        }}
      />
    );
  }

  return (
    <MainScreen
      connection={connection}
      status={status}
      busy={busy}
      error={error}
      notice={notice}
      blackKey={blackKey}
      keyName={keyName}
      onBlackKey={setBlackKey}
      onKeyName={setKeyName}
      onConnect={onConnect}
      onImportKey={onImportKey}
      onOpenAdvanced={openAdvanced}
    />
  );
}
