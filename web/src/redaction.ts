const SECRET_KEY_RE = /blackkey|password|secret|token/i;

export type PersistFn = (key: string, value: string) => void;

export function isSecretStorageKey(key: string): boolean {
  return SECRET_KEY_RE.test(key);
}

export function wouldPersistSecret(
  storageKey: string,
  value: string,
  secret: string,
): boolean {
  if (isSecretStorageKey(storageKey)) {
    return true;
  }
  return secret !== "" && value.includes(secret);
}

export function safePersist(
  persist: PersistFn,
  storageKey: string,
  value: string,
  secret: string,
): boolean {
  if (wouldPersistSecret(storageKey, value, secret)) {
    return false;
  }
  persist(storageKey, value);
  return true;
}

export function storageDumpContains(
  dump: Record<string, string>,
  secret: string,
): boolean {
  if (!secret) {
    return false;
  }
  return Object.values(dump).some((v) => v.includes(secret));
}

export type ImportKeyRequest = (body: {
  blackKey: string;
  name?: string;
}) => Promise<{ status: number }>;

export async function importBlackKey(options: {
  blackKey: string;
  name?: string;
  request: ImportKeyRequest;
  persist?: PersistFn;
}): Promise<{ status: number; nextFieldValue: string }> {
  const { blackKey, name, request, persist } = options;
  const body: { blackKey: string; name?: string } = { blackKey };
  if (name) {
    body.name = name;
  }
  const res = await request(body);
  if (persist) {
    safePersist(
      persist,
      "lastProfileImportStatus",
      String(res.status),
      blackKey,
    );
  }
  if (res.status === 201) {
    return { status: 201, nextFieldValue: "" };
  }
  if (res.status === 401) {
    return { status: 401, nextFieldValue: "" };
  }
  return { status: res.status, nextFieldValue: blackKey };
}
