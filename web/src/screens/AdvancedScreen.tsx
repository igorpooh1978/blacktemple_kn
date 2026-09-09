import {
  IconArrowLeft,
  IconCpu,
  IconInfoCircle,
  IconRefresh,
} from "../ui/tabler";
import type { Status, VersionInfo, XrayState } from "../api";
import { Alert } from "../ui/Alert";
import { Card } from "../ui/Card";
import { IconButton } from "../ui/IconButton";
import { ICON_SIZE, ICON_SIZE_SM, ICON_STROKE } from "../ui/icons";
import { SettingRow } from "../ui/SettingRow";
import { StatusBadge } from "../ui/StatusBadge";
import type { StatusTone } from "../ui/StatusBadge";

export function AdvancedScreen(props: {
  version: VersionInfo | null;
  status: Status;
  error: string;
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
