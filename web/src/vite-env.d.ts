/// <reference types="vite/client" />

declare module "@tabler/icons-preact/dist/esm/icons/*.mjs" {
  import type { FunctionComponent } from "preact";

  const Icon: FunctionComponent<{
    size?: number;
    stroke?: number;
    class?: string;
    title?: string;
    color?: string;
    "aria-hidden"?: boolean | "true" | "false";
  }>;
  export default Icon;
}
