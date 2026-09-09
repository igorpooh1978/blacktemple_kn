import type { ComponentChildren } from "preact";

export type StatusTone = "neutral" | "ok" | "wait" | "fail";

export function StatusBadge(props: {
  tone: StatusTone;
  children: ComponentChildren;
}) {
  return (
    <span class={`status-badge status-badge--${props.tone}`}>{props.children}</span>
  );
}
