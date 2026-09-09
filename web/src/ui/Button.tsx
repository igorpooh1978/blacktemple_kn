import type { ComponentChildren } from "preact";
import { Spinner } from "./Spinner";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

export function Button(props: {
  variant?: ButtonVariant;
  type?: "button" | "submit";
  disabled?: boolean;
  loading?: boolean;
  block?: boolean;
  icon?: ComponentChildren;
  children: ComponentChildren;
  onClick?: () => void;
  class?: string;
}) {
  const variant = props.variant ?? "primary";
  const loading = Boolean(props.loading);
  const className = [
    "btn",
    `btn-${variant}`,
    props.block ? "btn-block" : "",
    loading ? "is-loading" : "",
    props.class ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button
      type={props.type ?? "button"}
      class={className}
      disabled={props.disabled || loading}
      aria-busy={loading || undefined}
      onClick={props.onClick}
    >
      {props.icon || loading ? (
        <span class="btn-icon" aria-hidden="true">
          {loading ? <Spinner /> : props.icon}
        </span>
      ) : null}
      <span class="btn-label">{props.children}</span>
    </button>
  );
}
