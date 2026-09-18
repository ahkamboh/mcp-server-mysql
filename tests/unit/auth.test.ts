import { createHash } from "crypto";
import { beforeEach, describe, expect, it } from "vitest";
import * as OTPAuth from "otpauth";
import {
  buildTotp,
  resetTotpLimiter,
  TOTP_LOCK_AFTER,
  verifyTotp,
} from "../../src/auth/totp.js";
import {
  consumeAuthCode,
  issueAuthCode,
  mintAccessToken,
  resetSessionStore,
  TOKEN_TTL_SECONDS,
  verifyAccessToken,
  verifyPkce,
} from "../../src/auth/session.js";
import { handleAuthorizePost, handleToken } from "../../src/auth/http.js";

const secret = new OTPAuth.Secret({ size: 20 });
process.env.TOTP_SECRET = secret.base32;
process.env.AUTH_TOKEN_SECRET = "unit-test-auth-token-secret-32chars";

function currentCode(now = Date.now()): string {
  const totp = buildTotp();
  if (!totp) {
    throw new Error("TOTP was not configured");
  }
  return totp.generate({ timestamp: now });
}

function mockRes() {
  return {
    statusCode: 200,
    body: undefined as unknown,
    redirectUrl: undefined as string | undefined,
    headersSent: false,
    setHeader() {
      return this;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    type() {
      return this;
    },
    send(body: unknown) {
      this.body = body;
      return this;
    },
    redirect(code: number, url?: string) {
      this.statusCode = code;
      this.redirectUrl = url;
      return this;
    },
  };
}

function mockReq(body: Record<string, string>, ip = "203.0.113.10") {
  return {
    body,
    query: {},
    ip,
    socket: { remoteAddress: ip },
    protocol: "https",
    get() {
      return undefined;
    },
  } as any;
}

describe("TOTP", () => {
  beforeEach(() => {
    resetTotpLimiter();
    process.env.TOTP_SECRET = secret.base32;
  });

  it("accepts the current 6-digit code", () => {
    expect(verifyTotp(currentCode(), "10.0.0.1")).toEqual({ ok: true });
  });

  it("rejects a wrong code", () => {
    expect(verifyTotp("000000", "10.0.0.2")).toEqual({
      ok: false,
      reason: "invalid",
    });
  });

  it("locks the IP after 5 failures", () => {
    const ip = "10.0.0.3";
    for (let i = 0; i < TOTP_LOCK_AFTER; i++) {
      expect(verifyTotp("000000", ip).ok).toBe(false);
    }
    expect(verifyTotp(currentCode(), ip)).toEqual({
      ok: false,
      reason: "locked",
    });
  });
});

describe("access token platform claim", () => {
  beforeEach(() => {
    process.env.AUTH_TOKEN_SECRET = "unit-test-auth-token-secret-32chars";
    resetSessionStore();
  });

  it("embeds the selected platform", () => {
    const token = mintAccessToken("fundedocean");
    const claims = verifyAccessToken(token);
    expect(claims?.platform).toBe("fundedocean");
    expect(claims?.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect((claims?.exp || 0) - (claims?.iat || 0)).toBe(TOKEN_TTL_SECONDS);
  });

  it("rejects a tampered token and an expired token", () => {
    const token = mintAccessToken("global4ex");
    expect(verifyAccessToken(token.slice(0, -1) + "x")).toBeNull();
    const expired = mintAccessToken("global4ex", { ttlSeconds: -5 });
    expect(verifyAccessToken(expired)).toBeNull();
  });

  it("binds platform on the auth code and token exchange", () => {
    const code = issueAuthCode({
      platform: "fundedocean",
      redirectUri: "https://localhost/cb",
      clientId: "test-client",
    });
    const record = consumeAuthCode(code);
    expect(record?.platform).toBe("fundedocean");
    expect(consumeAuthCode(code)).toBeNull();
    const token = mintAccessToken(record!.platform, { clientId: record!.clientId });
    expect(verifyAccessToken(token)?.platform).toBe("fundedocean");
  });
});

describe("authorize form to token", () => {
  beforeEach(() => {
    resetTotpLimiter();
    resetSessionStore();
    process.env.TOTP_SECRET = secret.base32;
    process.env.AUTH_TOKEN_SECRET = "unit-test-auth-token-secret-32chars";
  });

  it("issues a FundedOcean token after a valid form post", () => {
    const verifier = "a".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorizeRes = mockRes();
    handleAuthorizePost(
      mockReq({
        platform: "fundedocean",
        code: currentCode(),
        redirect_uri: "https://localhost/cb",
        state: "xyz",
        client_id: "test-client",
        code_challenge: challenge,
        code_challenge_method: "S256",
        response_type: "code",
      }),
      authorizeRes as any,
    );

    expect(authorizeRes.statusCode).toBe(302);
    const redirected = new URL(authorizeRes.redirectUrl || "");
    expect(redirected.origin + redirected.pathname).toBe("https://localhost/cb");
    expect(redirected.searchParams.get("state")).toBe("xyz");
    const authCode = redirected.searchParams.get("code");
    expect(authCode).toBeTruthy();

    const tokenRes = mockRes();
    handleToken(
      {
        body: {
          grant_type: "authorization_code",
          code: authCode,
          code_verifier: verifier,
          redirect_uri: "https://localhost/cb",
          client_id: "test-client",
        },
      } as any,
      tokenRes as any,
    );

    expect(tokenRes.statusCode).toBe(200);
    const body = tokenRes.body as {
      access_token: string;
      token_type: string;
      expires_in: number;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(TOKEN_TTL_SECONDS);
    expect(verifyAccessToken(body.access_token)?.platform).toBe("fundedocean");
    expect(verifyPkce(verifier, challenge)).toBe(true);
  });
});
