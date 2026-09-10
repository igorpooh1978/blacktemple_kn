import {
  IconAlertTriangle,
  IconCheck,
  IconInfoCircle,
} from "./tabler";
import type { ComponentChildren } from "preact";
import { ICON_SIZE_SM, ICON_STROKE } from "./icons";

export type AlertTone = "info" | "warning" | "error" | "success";

export function Alert(props: { tone: AlertTone; children: ComponentChildren }) {
  const role = props.tone === "error" || props.tone === "warning" ? "alert" : "status";
  const icon =
    props.tone === "success" ? (
      <IconCheck size={ICON_SIZE_SM} stroke={ICON_STROKE} />
    ) : props.tone === "info" ? (
      <IconInfoCircle size={ICON_SIZE_SM} stroke={ICON_STROKE} />
    ) : (
      <IconAlertTriangle size={ICON_SIZE_SM} stroke={ICON_STROKE} />
    );

  return (
    <p class={`alert alert--${props.tone}`} role={role}>
      <span class="alert-icon" aria-hidden="true">
        {icon}
      </span>
      <span>{props.children}</span>
    </p>
  );
}
