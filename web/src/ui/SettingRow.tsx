import { IconCheck, IconChevronRight } from "./tabler";
import type { ComponentChildren } from "preact";
import { ICON_SIZE, ICON_SIZE_SM, ICON_STROKE } from "./icons";

export function SettingRow(props: {
  icon: ComponentChildren;
  title: string;
  value: ComponentChildren;
  interactive?: boolean;
  trailing?: "chevron" | "check" | "none";
  onClick?: () => void;
}) {
  const trailing =
    props.trailing ?? (props.interactive ? "chevron" : "none");
  const body = (
    <>
      <span class="setting-icon" aria-hidden="true">
        {props.icon}
      </span>
      <span class="setting-copy">
        <span class="setting-title">{props.title}</span>
        <span class="setting-value">{props.value}</span>
      </span>
      {trailing === "chevron" ? (
        <IconChevronRight
          class="setting-trailing"
          size={ICON_SIZE}
          stroke={ICON_STROKE}
          aria-hidden="true"
        />
      ) : null}
      {trailing === "check" ? (
        <IconCheck
          class="setting-trailing setting-trailing--ok"
          size={ICON_SIZE_SM}
          stroke={ICON_STROKE}
          aria-hidden="true"
        />
      ) : null}
    </>
  );

  if (props.interactive) {
    return (
      <button type="button" class="setting-row setting-row--interactive" onClick={props.onClick}>
        {body}
      </button>
    );
  }

  return <div class="setting-row">{body}</div>;
}
