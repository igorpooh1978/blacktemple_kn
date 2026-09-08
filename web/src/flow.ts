export type Screen = "setup" | "login" | "main" | "advanced";

export function screenAfterSetupStatus(
  httpStatus: number,
): "login" | "authenticate" | "stay" {
  if (httpStatus === 409) {
    return "login";
  }
  if (httpStatus === 204) {
    return "authenticate";
  }
  return "stay";
}

export function defaultDisconnectedStatus(): {
  connection: "disconnected";
  routing: "smart";
  serverMode: "auto";
  key: "missing";
} {
  return {
    connection: "disconnected",
    routing: "smart",
    serverMode: "auto",
    key: "missing",
  };
}
