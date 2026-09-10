import type { ComponentChildren } from "preact";

export function Card(props: { children: ComponentChildren; class?: string }) {
  return (
    <div class={["card", props.class ?? ""].filter(Boolean).join(" ")}>
      {props.children}
    </div>
  );
}
