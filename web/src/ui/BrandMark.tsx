import { IconShieldCheck } from "./tabler";
import { ICON_STROKE } from "./icons";

export function BrandMark({ size = 48 }: { size?: number }) {
  return (
    <span class="brand-mark" aria-hidden="true">
      <IconShieldCheck size={Math.round(size * 0.52)} stroke={ICON_STROKE} />
    </span>
  );
}
