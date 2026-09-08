import type { ConnectionState } from "./api";

export const VPN_ENGINE_NOT_READY = "VPN engine ещё не готов";

export type ConnectionPostResult = {
  notice: string;
  /** UI must not set connected from this POST. Caller may refetch GET /status. */
  refetch: boolean;
};

/**
 * Connection LED/state is driven only by GET /api/v1/status.
 * POST 202 means accepted, not connected. POST 501 never looks connected.
 */
export function interpretConnectionPost(
  httpStatus: number,
  _previous: ConnectionState,
): ConnectionPostResult {
  if (httpStatus === 501) {
    return { notice: VPN_ENGINE_NOT_READY, refetch: false };
  }
  if (httpStatus === 202) {
    return { notice: "", refetch: true };
  }
  return { notice: "Не удалось изменить подключение", refetch: true };
}
