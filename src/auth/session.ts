import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "crypto";
import { Brand, isBrand } from "../config/index.js";

export const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
export const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

export type AccessTokenClaims = {
  platform: Brand;
  exp: number;
  iat: number;
  clientId: string;
};

type TokenPayload = {
  p: Brand;
  exp: number;
  iat: number;
  cid: string;
};

export type AuthCodeRecord = {
  platform: Brand;
  redirectUri: string;
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: "S256";
  state?: string;
  exp: number;
};

export type RegisteredClient = {
  client_id: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  client_secret?: string;
  client_name?: string;
  client_id_issued_at: number;
};

const codes = new Map<string, AuthCodeRecord>();
const clients = new Map<string, RegisteredClient>();

function authSecret(): string {
  return (process.env.AUTH_TOKEN_SECRET || "").trim();
}

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function hmac(body: string): string {
  const secret = authSecret();
  if (!secret) {
    throw new Error("AUTH_TOKEN_SECRET is not set");
  }
  return createHmac("sha256", secret).update(body).digest("base64url");
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export function mintAccessToken(
  platform: Brand,
  options: { clientId?: string; ttlSeconds?: number; now?: number } = {},
): string {
  if (!isBrand(platform)) {
    throw new Error("Invalid platform");
  }
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const ttl = options.ttlSeconds ?? TOKEN_TTL_SECONDS;
  const payload: TokenPayload = {
    p: platform,
    iat: now,
    exp: now + ttl,
    cid: options.clientId || "mcp",
  };
  const body = b64urlJson(payload);
  return `${body}.${hmac(body)}`;
}

export function verifyAccessToken(token: string): AccessTokenClaims | null {
  if (!token || !authSecret()) {
    return null;
  }
  const parts = token.trim().split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [body, sig] = parts;
  if (!body || !sig) {
    return null;
  }
  let expected: string;
  try {
    expected = hmac(body);
  } catch {
    return null;
  }
  if (!safeEqual(sig, expected)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as TokenPayload;
    if (!isBrand(parsed.p) || typeof parsed.exp !== "number" || typeof parsed.iat !== "number") {
      return null;
    }
    const now = Math.floor(Date.now() / 1000);
    if (parsed.exp <= now) {
      return null;
    }
    return {
      platform: parsed.p,
      exp: parsed.exp,
      iat: parsed.iat,
      clientId: parsed.cid || "mcp",
    };
  } catch {
    return null;
  }
}

export function parseBearerToken(header: string | undefined): string | null {
  if (!header) {
    return null;
  }
  const match = header.match(/^Bearer\s+(\S+)/i);
  return match ? match[1] : null;
}

export function issueAuthCode(
  record: Omit<AuthCodeRecord, "exp">,
  now = Date.now(),
): string {
  const code = randomBytes(32).toString("base64url");
  codes.set(code, { ...record, exp: now + AUTH_CODE_TTL_MS });
  return code;
}

export function consumeAuthCode(code: string, now = Date.now()): AuthCodeRecord | null {
  if (!code) {
    return null;
  }
  const record = codes.get(code);
  if (!record) {
    return null;
  }
  codes.delete(code);
  if (record.exp <= now) {
    return null;
  }
  return record;
}

export function verifyPkce(verifier: string, challenge: string): boolean {
  if (!verifier || !challenge) {
    return false;
  }
  const computed = createHash("sha256").update(verifier).digest("base64url");
  if (computed.length !== challenge.length) {
    return false;
  }
  return safeEqual(computed, challenge);
}

export function isSafeRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol === "javascript:" || parsed.protocol === "data:") {
      return false;
    }
    if (parsed.protocol === "https:") {
      return true;
    }
    if (
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
    ) {
      return true;
    }
    return /^[a-z][a-z0-9+.-]*:$/.test(parsed.protocol);
  } catch {
    return false;
  }
}

export function registerClient(meta: {
  redirect_uris?: string[];
  token_endpoint_auth_method?: string;
  client_name?: string;
  client_secret?: string;
}): RegisteredClient {
  const client_id = randomUUID();
  const record: RegisteredClient = {
    client_id,
    redirect_uris: Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [],
    token_endpoint_auth_method: meta.token_endpoint_auth_method || "none",
    client_name: meta.client_name,
    client_secret: meta.client_secret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
  };
  clients.set(client_id, record);
  return record;
}

export function getClient(clientId: string): RegisteredClient | undefined {
  return clients.get(clientId);
}

export function redirectUriAllowed(clientId: string | undefined, redirectUri: string): boolean {
  if (!isSafeRedirectUri(redirectUri)) {
    return false;
  }
  if (!clientId) {
    return true;
  }
  const client = clients.get(clientId);
  if (!client) {
    return true;
  }
  if (client.redirect_uris.length === 0) {
    return true;
  }
  return client.redirect_uris.includes(redirectUri);
}

export function resetSessionStore(): void {
  codes.clear();
  clients.clear();
}
