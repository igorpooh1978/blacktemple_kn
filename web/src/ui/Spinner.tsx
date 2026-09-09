import { IconLoader2 } from "./tabler";
import { ICON_SIZE_SM, ICON_STROKE } from "./icons";

export function Spinner({ size = ICON_SIZE_SM }: { size?: number }) {
  return (
    <IconLoader2
      class="spinner"
      size={size}
      stroke={ICON_STROKE}
      aria-hidden="true"
    />
  );
}
