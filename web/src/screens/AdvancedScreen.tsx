import {
  IconArrowLeft,
  IconCpu,
  IconInfoCircle,
  IconLock,
  IconLogout,
  IconRefresh,
} from "../ui/tabler";
import type { Status, VersionInfo, XrayState } from "../api";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Field } from "../ui/Field";
import { IconButton } from "../ui/IconButton";
import { ICON_SIZE, ICON_SIZE_SM, ICON_STROKE } from "../ui/icons";
import { SettingRow } from "../ui/SettingRow";
import { StatusBadge } from "../ui/StatusBadge";
import type { StatusTone } from "../ui/StatusBadge";
import { noticeAlertTone } from "../labels";

export function AdvancedScreen(props: {
  version: VersionInfo | null;
  status: Status;
  error: string;
  notice: string;
  busy: boolean;
  currentPassword: string;
  newPassword: string;
  newRepeat: string;
  onCurrentPassword: (value: string) => void;
  onNewPassword: (value: string) => void;
  onNewRepeat: (value: string) => void;
  onChangePassword: (ev: Event) => void;
  onLogout: () => void;
  onBack: () => void;
}) {
  const xray = props.status.xray;
  const pid =
    xray?.pid === null || xray?.pid === undefined ? "—" : String(xray.pid);
  const restarts =
    xray?.restartCount === undefined ? "—" : String(xray.restartCount);
  const xrayState = xray?.state ?? "—";

  return (
    <main class="shell">
      <header class="topbar">
        <div class="topbar-start">
          <IconButton label="Назад" onClick={props.onBack}>
            <IconArrowLeft size={ICON_SIZE} stroke={ICON_STROKE} />
          </IconButton>
          <h1 class="page-title">Дополнительно</h1>
        </div>
      </header>
      {props.error ? <Alert tone="error">{props.error}</Alert> : null}
      {props.notice ? (
        <Alert tone={noticeAlertTone(props.notice)}>{props.notice}</Alert>
      ) : null}
      <Card class="facts-card">
        <SettingRow
          icon={<IconInfoCircle size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Версия"
          value={props.version?.version ?? "—"}
        />
        <SettingRow
          icon={<IconCpu size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Xray"
          value={<StatusBadge tone={xrayTone(xray?.state)}>{xrayState}</StatusBadge>}
        />
        <SettingRow
          icon={<IconCpu size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="PID"
          value={pid}
        />
        <SettingRow
          icon={<IconRefresh size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          title="Перезапусков"
          value={restarts}
        />
        {props.status.errorClass ? (
          <SettingRow
            icon={<IconInfoCircle size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
            title="Класс ошибки"
            value={props.status.errorClass}
          />
        ) : null}
      </Card>
      <Card>
        <h2 class="auth-title">Пароль панели</h2>
        <p class="lead">Смена пароля входа в BlackTemple KN, не пароля Keenetic.</p>
        <form class="auth-form" onSubmit={props.onChangePassword}>
          <Field label="Текущий пароль">
            <input
              type="password"
              name="currentPassword"
              autocomplete="current-password"
              value={props.currentPassword}
              onInput={(e) =>
                props.onCurrentPassword((e.target as HTMLInputElement).value)
              }
            />
          </Field>
          <Field label="Новый пароль">
            <input
              type="password"
              name="newPassword"
              autocomplete="new-password"
              value={props.newPassword}
              onInput={(e) =>
                props.onNewPassword((e.target as HTMLInputElement).value)
              }
            />
          </Field>
          <Field label="Повторите новый пароль">
            <input
              type="password"
              name="newRepeat"
              autocomplete="new-password"
              value={props.newRepeat}
              onInput={(e) =>
                props.onNewRepeat((e.target as HTMLInputElement).value)
              }
            />
          </Field>
          <Button
            type="submit"
            block
            disabled={props.busy}
            loading={props.busy}
            icon={<IconLock size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          >
            Сменить пароль
          </Button>
        </form>
        <p class="auth-aux">
          <Button
            variant="ghost"
            block
            disabled={props.busy}
            onClick={props.onLogout}
            icon={<IconLogout size={ICON_SIZE_SM} stroke={ICON_STROKE} />}
          >
            Выйти
          </Button>
        </p>
      </Card>
    </main>
  );
}

function xrayTone(state: XrayState | undefined): StatusTone {
  switch (state) {
    case "RUNNING":
      return "ok";
    case "STARTING":
    case "RELOADING":
      return "wait";
    case "FAILED":
    case "BACKOFF":
      return "fail";
    case "STOPPED":
    case undefined:
      return "neutral";
    default: {
      const _never: never = state;
      return _never;
    }
  }
}
