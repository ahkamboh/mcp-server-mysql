import * as OTPAuth from "otpauth";

export const TOTP_ACCOUNT = "sqlmcp:ahkamboh";
export const TOTP_ISSUER = "sqlmcp";
export const TOTP_LABEL = "ahkamboh";
export const TOTP_WINDOW = 1;
export const TOTP_LOCK_AFTER = 5;
export const TOTP_LOCK_MS = 10 * 60 * 1000;

export type TotpFailureReason = "locked" | "invalid";
export type TotpResult =
  | { ok: true }
  | { ok: false; reason: TotpFailureReason };

type FailState = {
  count: number;
  lockedUntil: number;
};

const failures = new Map<string, FailState>();

function normalizeSecret(raw: string): string {
  return raw.replace(/\s+/g, "").toUpperCase();
}

function getSecret(): OTPAuth.Secret | null {
  const raw = process.env.TOTP_SECRET || "";
  if (!raw.trim()) {
    return null;
  }
  try {
    return OTPAuth.Secret.fromBase32(normalizeSecret(raw));
  } catch {
    return null;
  }
}

export function buildTotp(secret?: OTPAuth.Secret): OTPAuth.TOTP | null {
  const resolved = secret ?? getSecret();
  if (!resolved) {
    return null;
  }
  return new OTPAuth.TOTP({
    issuer: TOTP_ISSUER,
    label: TOTP_LABEL,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: resolved,
  });
}

function recordFailure(ip: string, now: number): void {
  const state = failures.get(ip) || { count: 0, lockedUntil: 0 };
  if (state.lockedUntil > now) {
    return;
  }
  if (state.lockedUntil > 0 && state.lockedUntil <= now) {
    state.count = 0;
    state.lockedUntil = 0;
  }
  state.count += 1;
  if (state.count >= TOTP_LOCK_AFTER) {
    state.lockedUntil = now + TOTP_LOCK_MS;
  }
  failures.set(ip, state);
}

export function isTotpLocked(ip: string, now = Date.now()): boolean {
  const state = failures.get(ip);
  return Boolean(state && state.lockedUntil > now);
}

export function verifyTotp(code: string, ip: string, now = Date.now()): TotpResult {
  const key = ip || "unknown";
  if (isTotpLocked(key, now)) {
    return { ok: false, reason: "locked" };
  }

  const token = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(token)) {
    recordFailure(key, now);
    return { ok: false, reason: "invalid" };
  }

  const totp = buildTotp();
  if (!totp) {
    recordFailure(key, now);
    return { ok: false, reason: "invalid" };
  }

  const delta = totp.validate({ token, window: TOTP_WINDOW, timestamp: now });
  if (delta === null) {
    recordFailure(key, now);
    return { ok: false, reason: "invalid" };
  }

  failures.delete(key);
  return { ok: true };
}

export function resetTotpLimiter(): void {
  failures.clear();
}
