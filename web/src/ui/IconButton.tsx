import type { ComponentChildren } from "preact";

export function IconButton(props: {
  label: string;
  disabled?: boolean;
  onClick?: () => void;
  children: ComponentChildren;
}) {
  return (
    <button
      type="button"
      class="icon-btn"
      aria-label={props.label}
      disabled={props.disabled}
      onClick={props.onClick}
    >
      <span aria-hidden="true">{props.children}</span>
    </button>
  );
}
