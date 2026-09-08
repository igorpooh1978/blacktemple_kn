import { describe, expect, it, vi } from "vitest";
import {
  importBlackKey,
  isSecretStorageKey,
  safePersist,
  storageDumpContains,
} from "./redaction";

function memoryPersist() {
  const dump: Record<string, string> = {};
  return {
    dump,
    persist(key: string, value: string) {
      dump[key] = value;
    },
  };
}

describe("BlackKey redaction", () => {
  it("refuses storage keys that look like secrets", () => {
    expect(isSecretStorageKey("blackKey")).toBe(true);
    expect(isSecretStorageKey("password")).toBe(true);
    expect(isSecretStorageKey("lastProfileImportStatus")).toBe(false);
  });

  it("does not persist the raw key after a successful import", async () => {
    const store = memoryPersist();
    const secret = "bk_test_raw_key_value_do_not_store";
    const request = vi.fn().mockResolvedValue({ status: 201 });

    const result = await importBlackKey({
      blackKey: secret,
      name: "home",
      request,
      persist: store.persist,
    });

    expect(result.status).toBe(201);
    expect(result.nextFieldValue).toBe("");
    expect(request).toHaveBeenCalledWith({ blackKey: secret, name: "home" });
    expect(storageDumpContains(store.dump, secret)).toBe(false);
    expect(store.dump.lastProfileImportStatus).toBe("201");
    expect(JSON.stringify(store.dump)).not.toContain(secret);
  });

  it("never writes blackKey into storage even if asked", () => {
    const store = memoryPersist();
    const secret = "bk_another_secret";
    const wrote = safePersist(store.persist, "blackKey", secret, secret);
    expect(wrote).toBe(false);
    expect(store.dump.blackKey).toBeUndefined();
    expect(storageDumpContains(store.dump, secret)).toBe(false);
  });
});
