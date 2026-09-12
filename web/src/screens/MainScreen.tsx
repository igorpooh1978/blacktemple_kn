import {
  IconAlertTriangle,
  IconInfoCircle,
  IconKey,
  IconPower,
  IconRoute,
  IconServer,
  IconSettings,
  IconShieldCheck,
  IconShieldOff,
} from "../ui/tabler";
import { useEffect, useRef } from "preact/hooks";
import type { ConnectionState, Profile, Status } from "../api";
import {
  connectionActionLabel,
  connectionLabel,
  countryLabel,
  geodataLabel,
  keyLabel,
  latencyLabel,
  noticeAlertTone,
  profileDisplayName,
  profileStatusLabel,
  routingLabel,
  serverLabel,
  statusSummary,
} from "../labels";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Field } from "../ui/Field";
import { IconButton } from "../ui/IconButton";
import { ICON_SIZE, ICON_SIZE_LG, ICON_SIZE_SM, ICON_STROKE } from "../ui/icons";
import { SettingRow } from "../ui/SettingRow";
import { Spinner } from "../ui/Spinner";

export function MainScreen(props: {
  connection: ConnectionState;
  status: Status;
  profiles: Profile[];
  busy: boolean;
  error: string;
  notice: string;
  blackKey: string;
  keyName: string;
  onBlackKey: (value: string) => void;
  onKeyName: (value: string) => void;
  onConnect: () => void;
  onImportKey: (ev: Event) => void;
  onOpenAdvanced: () => void;
}) {
  const keyForm = useRef<HTMLDetailsElement>(null);
  const keyInput = useRef<HTMLInputElement>(null);
  const connecting = props.connection === "connecting";
  const connected = props.connection === "connected";
  const keyReady = props.status.key === "active";

  useEffect(() => {
    if (
      (props.notice === "Готово" || props.notice.startsWith("Получено ")) &&
      keyForm.current
    ) {
      keyForm.current.open = false;
    }
  }, [props.notice]);

  useEffect(() => {
    if (props.blackKey === "" && keyInput.current) {
      keyInput.current.value = "";
    }
  }, [props.blackKey]);

  return (
    <main class="shell">
      <header class="topbar">
        <h1 class="topbar-title">BlackTemple KN</h1>
        <IconButton label="Дополнительно" onClick={props.onOpenAdvanced}>
          <IconSettings size={ICON_SIZE} stroke={ICON_STROKE} />
        </IconButton>
      </header>

      <section class="hero" data-state={props.connection}>
        <div class="hero-orb" aria-hidden="true">
          {heroIcon(props.connection)}
        </div>
        <h2 class="hero-title" aria-live="polite">
          {connectionLabel(props.connection)}
        </h2>
        <p class="hero-sub">{statusSummary(props.status)}</p>
        <div class="hero-action">
          <Button
            variant={connected ? "secondary" : "primary"}
            block
            disabled={props.busy || connecting}
            loading={props.busy || connecting}
            icon={<IconPower size={22} stroke={ICON_STROKE} />}
            onClick={props.onConnect}
          >
            {connectionActionLabel(props.connection)}
          </Button>
        </div>
      </section>

      {props.notice ? (
        <Alert tone={noticeAlertTone(props.notice)}>{props.notice}</Alert>
      ) : null}
      {props.error ? <Alert tone="error">{props.error}</Alert> : null}

      <p class="section-label">Соединение</p>
      <Card class="panel">
        <SettingRow
          icon={<IconServer size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Сервер"
          value={serverLabel(props.status.serverMode)}
        />
        <SettingRow
          icon={<IconServer size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Страна"
          value={countryLabel(props.status.country)}
        />
        <SettingRow
          icon={<IconRoute size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Задержка"
          value={latencyLabel(props.status.latencyMs)}
        />
        <SettingRow
          icon={<IconRoute size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Маршрутизация"
          value={routingLabel(props.status.routing)}
        />
        <SettingRow
          icon={<IconInfoCircle size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Геоданные"
          value={geodataLabel(props.status.geodata)}
        />
        <SettingRow
          icon={<IconKey size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="BlackKey"
          value={keyLabel(props.status.key)}
          trailing={keyReady ? "check" : "none"}
        />
        {props.profiles.map((profile) => (
          <SettingRow
            key={profile.id}
            icon={<IconKey size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
            title={profileDisplayName(profile)}
            value={profileStatusLabel(profile.status)}
            trailing={profile.status === "active" ? "check" : "none"}
          />
        ))}
        <details ref={keyForm} class="key-disclose">
          <summary>
            <IconKey size={ICON_SIZE_SM} stroke={ICON_STROKE} aria-hidden="true" />
            Добавить ключ
          </summary>
          <form class="key-form" onSubmit={props.onImportKey}>
            <Field label="BlackKey">
              <input
                ref={keyInput}
                type="password"
                name="blackKey"
                autocomplete="off"
                onInput={(e) =>
                  props.onBlackKey((e.currentTarget as HTMLInputElement).value)
                }
              />
            </Field>
            <Field label="Имя, необязательно">
              <input
                type="text"
                name="keyName"
                autocomplete="off"
                value={props.keyName}
                onInput={(e) =>
                  props.onKeyName((e.target as HTMLInputElement).value)
                }
              />
            </Field>
            <Button
              type="submit"
              variant="secondary"
              block
              disabled={props.busy}
              loading={props.busy}
              icon={<IconKey size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
            >
              {props.busy ? "Получение серверов..." : "Добавить ключ"}
            </Button>
          </form>
        </details>
      </Card>

      <Card class="footer-row">
        <SettingRow
          icon={<IconSettings size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Дополнительно"
          value="Система и версия"
          interactive
          onClick={props.onOpenAdvanced}
        />
      </Card>
    </main>
  );
}

function heroIcon(connection: ConnectionState) {
  if (connection === "connected") {
    return <IconShieldCheck size={ICON_SIZE_LG} stroke={ICON_STROKE} />;
  }
  if (connection === "connecting") {
    return <Spinner size={ICON_SIZE_LG} />;
  }
  if (connection === "failed") {
    return <IconAlertTriangle size={ICON_SIZE_LG} stroke={ICON_STROKE} />;
  }
  return <IconShieldOff size={ICON_SIZE_LG} stroke={ICON_STROKE} />;
}
