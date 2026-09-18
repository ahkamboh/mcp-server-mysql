import { existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import type { Request, Response } from "express";
import { isBrand, type Brand } from "../config/index.js";
import { verifyTotp } from "./totp.js";
import {
  consumeAuthCode,
  getClient,
  issueAuthCode,
  isSafeRedirectUri,
  mintAccessToken,
  parseBearerToken,
  redirectUriAllowed,
  registerClient,
  TOKEN_TTL_SECONDS,
  verifyAccessToken,
  verifyPkce,
  type AccessTokenClaims,
} from "./session.js";

const OAUTH_HIDDEN = [
  "client_id",
  "redirect_uri",
  "state",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "scope",
  "resource",
] as const;

function publicDir(): string {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(dir, "..", "..", "..", "public"),
    path.join(dir, "..", "..", "public"),
    path.join(dir, "public"),
  ];
  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, "authorize.html"))) {
      return candidate;
    }
  }
  return candidates[0];
}

export function authorizeHtmlPath(): string {
  return path.join(publicDir(), "authorize.html");
}

export function faviconPath(): string {
  return path.join(publicDir(), "favicon.ico");
}

export function publicBase(req: Request): string {
  const configured = (process.env.PUBLIC_URL || "").trim().replace(/\/$/, "");
  if (configured) {
    return configured;
  }
  const protoHeader = req.get("x-forwarded-proto") || req.protocol || "https";
  const proto = protoHeader.split(",")[0].trim();
  return `${proto}://${req.get("host")}`;
}

export function clientIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || "unknown";
}

export function oauthMetadata(req: Request) {
  const base = publicBase(req);
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: ["mcp:tools"],
  };
}

export function protectedResourceMetadata(req: Request) {
  const base = publicBase(req);
  return {
    resource: `${base}/mcp`,
    authorization_servers: [base],
    scopes_supported: ["mcp:tools"],
    resource_name: "mcp-server-mysql",
  };
}

function field(body: Record<string, unknown>, query: Request["query"], name: string): string {
  const fromBody = body[name];
  if (typeof fromBody === "string") {
    return fromBody;
  }
  const fromQuery = query[name];
  return typeof fromQuery === "string" ? fromQuery : "";
}

export function sendAuthorizePage(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(authorizeHtmlPath(), (err) => {
    if (err && !res.headersSent) {
      res.status(500).type("html").send("Authorize page is missing");
    }
  });
}

export function handleAuthorizePost(req: Request, res: Response): void {
  const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<
    string,
    unknown
  >;
  const platformRaw = field(body, req.query, "platform");
  const totp = field(body, req.query, "code");
  const redirectUri = field(body, req.query, "redirect_uri");
  const state = field(body, req.query, "state");
  const clientId = field(body, req.query, "client_id") || "mcp";
  const codeChallenge = field(body, req.query, "code_challenge");
  const codeChallengeMethod = field(body, req.query, "code_challenge_method");
  const responseType = field(body, req.query, "response_type") || "code";

  const replay = new URLSearchParams();
  for (const name of OAUTH_HIDDEN) {
    const value = field(body, req.query, name);
    if (value) {
      replay.set(name, value);
    }
  }
  if (platformRaw) {
    replay.set("platform", platformRaw);
  }

  if (!isBrand(platformRaw)) {
    replay.set("error", "platform");
    res.redirect(303, `/authorize?${replay.toString()}`);
    return;
  }

  const totpResult = verifyTotp(totp, clientIp(req));
  if (!totpResult.ok) {
    replay.set("error", totpResult.reason);
    res.redirect(303, `/authorize?${replay.toString()}`);
    return;
  }

  if (responseType && responseType !== "code") {
    replay.set("error", "oauth");
    res.redirect(303, `/authorize?${replay.toString()}`);
    return;
  }

  if (!redirectUri) {
    res
      .status(200)
      .type("html")
      .send(
        `<!doctype html><html><body><p>Signed in for ${platformRaw}. Add this MCP from Claude or your host so it can finish the login.</p></body></html>`,
      );
    return;
  }

  if (!redirectUriAllowed(clientId, redirectUri) || !isSafeRedirectUri(redirectUri)) {
    replay.set("error", "oauth");
    res.redirect(303, `/authorize?${replay.toString()}`);
    return;
  }

  if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== "S256") {
    replay.set("error", "oauth");
    res.redirect(303, `/authorize?${replay.toString()}`);
    return;
  }

  const authCode = issueAuthCode({
    platform: platformRaw,
    redirectUri,
    clientId,
    codeChallenge: codeChallenge || undefined,
    codeChallengeMethod: codeChallenge ? "S256" : undefined,
    state: state || undefined,
  });

  const target = new URL(redirectUri);
  target.searchParams.set("code", authCode);
  if (state) {
    target.searchParams.set("state", state);
  }
  res.redirect(302, target.toString());
}

export function handleToken(req: Request, res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<
    string,
    unknown
  >;
  const grantType = typeof body.grant_type === "string" ? body.grant_type : "";
  const code = typeof body.code === "string" ? body.code : "";
  const codeVerifier = typeof body.code_verifier === "string" ? body.code_verifier : "";
  const redirectUri = typeof body.redirect_uri === "string" ? body.redirect_uri : "";
  const clientId = typeof body.client_id === "string" ? body.client_id : "";

  if (grantType !== "authorization_code") {
    res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Only authorization_code is supported",
    });
    return;
  }

  const record = consumeAuthCode(code);
  if (!record) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
    return;
  }

  if (redirectUri && redirectUri !== record.redirectUri) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "redirect_uri does not match",
    });
    return;
  }

  if (clientId && record.clientId && clientId !== record.clientId) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "client_id does not match",
    });
    return;
  }

  if (record.codeChallenge) {
    if (!verifyPkce(codeVerifier, record.codeChallenge)) {
      res.status(400).json({
        error: "invalid_grant",
        error_description: "code_verifier does not match",
      });
      return;
    }
  }

  try {
    const accessToken = mintAccessToken(record.platform, {
      clientId: record.clientId,
    });
    res.status(200).json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_SECONDS,
      scope: "mcp:tools",
    });
  } catch {
    res.status(500).json({
      error: "server_error",
      error_description: "AUTH_TOKEN_SECRET is not set",
    });
  }
}

export function handleRegister(req: Request, res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  const body = (req.body && typeof req.body === "object" ? req.body : {}) as {
    redirect_uris?: string[];
    token_endpoint_auth_method?: string;
    client_name?: string;
  };
  const client = registerClient({
    redirect_uris: body.redirect_uris,
    token_endpoint_auth_method: body.token_endpoint_auth_method || "none",
    client_name: body.client_name,
  });
  res.status(201).json(client);
}

export function requireMcpSession(
  req: Request,
  res: Response,
): AccessTokenClaims | null {
  const token = parseBearerToken(req.get("Authorization"));
  const session = token ? verifyAccessToken(token) : null;
  if (!session) {
    const metadata = `${publicBase(req)}/.well-known/oauth-protected-resource`;
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${metadata}"`,
    );
    res.status(401).json({
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "Missing or invalid Authorization header",
      },
      id: null,
    });
    return null;
  }
  return session;
}

export function resolveBrandFromEnv(): Brand {
  return isBrand(process.env.MCP_BRAND) ? process.env.MCP_BRAND : "global4ex";
}

export { getClient };
