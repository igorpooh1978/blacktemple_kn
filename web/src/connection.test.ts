import { describe, expect, it } from "vitest";
import {
  interpretConnectionPost,
  VPN_ENGINE_NOT_READY,
} from "./connection";

describe("connection POST", () => {
  it("shows engine notice on 501 and does not refetch as connected", () => {
    const result = interpretConnectionPost(501, "disconnected");
    expect(result.notice).toBe(VPN_ENGINE_NOT_READY);
    expect(result.refetch).toBe(false);
  });

  it("does not treat 202 as connected", () => {
    const result = interpretConnectionPost(202, "disconnected");
    expect(result.notice).toBe("");
    expect(result.refetch).toBe(true);
  });

  it("never upgrades previous state from a 501 POST", () => {
    const fromDisconnected = interpretConnectionPost(501, "disconnected");
    const fromConnecting = interpretConnectionPost(501, "connecting");
    expect(fromDisconnected.refetch).toBe(false);
    expect(fromConnecting.refetch).toBe(false);
    expect(fromDisconnected.notice).toBe(VPN_ENGINE_NOT_READY);
  });
});
