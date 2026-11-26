/**
 * OAuth sign-in for the hosted MCP server, through the deployed Worker against real D1: the
 * metadata documents, the consent routes the web app's consent page calls, the token endpoint it
 * forwards, and the issued token used at `/mcp` and directly against the API. Client metadata
 * documents come from the outbound fixture (`test/fixtures/oauth-client-metadata.ts`).
 */

import { createExecutionContext, env } from "cloudflare:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PermissionId } from "@open-inspect/shared/rbac";
import type {
  OAuthAuthorizationRequest,
  OAuthConsentResponse,
} from "@open-inspect/shared/types/oauth";
import type { PersonalAccessTokenPolicy } from "@open-inspect/shared/types/personal-access-tokens";
import { hashToken } from "../../src/auth/crypto";
import { OAuthAuthorizationCodeStore } from "../../src/db/oauth-authorization-codes";
import { PersonalAccessTokenStore } from "../../src/db/personal-access-tokens";
import { s256CodeChallenge } from "../../src/oauth/pkce";
import { TEST_CLIENT_ORIGIN } from "../fixtures/oauth-client-metadata";
import { cleanD1Tables } from "./cleanup";
import {
  initSession,
  routeRequest,
  serviceFetch,
  serviceRequestHeaders,
  sqlDatabase,
} from "./helpers";

const BASE = "https://cp.test";
const RESOURCE = `${BASE}/mcp`;
const ISSUER = new URL(env.WEB_APP_URL!).origin;
const CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_CODE = "https://claude.ai/oauth/claude-code-client-metadata";
const TEST_CLIENT = `${TEST_CLIENT_ORIGIN}/metadata`;
const OWNER = "77777777777777777777777777777777";
const ADMIN = { userId: "99999999999999999999999999999999", role: "administrator" } as const;

/** The deployment as production configures it: the control plane knows its own public URL. */
const deployed = { ...env, WORKER_URL: BASE };

function controlPlane(path: string, init: RequestInit = {}, bindings: typeof env = deployed) {
  return routeRequest(new Request(`${BASE}${path}`, init), bindings, createExecutionContext());
}

/** A consent route, as the web app's consent page calls it for the signed-in user. */
async function asUser(
  path: string,
  body: unknown,
  userId = OWNER,
  role: "owner" | "viewer" = "owner"
) {
  const serialized = JSON.stringify(body);
  const headers = await serviceRequestHeaders(`${BASE}${path}`, {
    method: "POST",
    body: serialized,
    as: { userId, role },
  });
  return controlPlane(path, { method: "POST", headers, body: serialized });
}

/** A web-app-only route, as the web app forwards it. */
async function asWebApp(path: string, init: { method?: string; body?: unknown } = {}) {
  const body = init.body === undefined ? undefined : JSON.stringify(init.body);
  const headers = await serviceRequestHeaders(`${BASE}${path}`, { method: init.method, body });
  return controlPlane(path, { method: init.method ?? "GET", headers, body });
}

async function pkce() {
  const verifier = `${crypto.randomUUID()}-${crypto.randomUUID()}`;
  return { verifier, challenge: await s256CodeChallenge(verifier) };
}

async function authorizationRequest(
  overrides: Partial<OAuthAuthorizationRequest> = {}
): Promise<{ request: OAuthAuthorizationRequest; verifier: string }> {
  const { verifier, challenge } = await pkce();
  return {
    verifier,
    request: {
      response_type: "code",
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
      state: "state-1",
      scope: "sessions.read",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: RESOURCE,
      ...overrides,
    },
  };
}

async function check(request: OAuthAuthorizationRequest, userId = OWNER) {
  const response = await asUser("/oauth/authorize/check", request, userId);
  expect(response.status).toBe(200);
  return response.json<OAuthConsentResponse>();
}

async function approve(
  request: OAuthAuthorizationRequest,
  permissions: PermissionId[] = ["sessions.read"],
  expiresInDays = 30
) {
  return asUser("/oauth/authorize/approve", { request, permissions, expiresInDays });
}

/** Approve and return the code the browser would carry back to the client. */
async function approvedCode(
  request: OAuthAuthorizationRequest,
  permissions?: PermissionId[],
  expiresInDays?: number
): Promise<string> {
  const response = await approve(request, permissions, expiresInDays);
  expect(response.status).toBe(200);
  const { redirectUrl } = await response.json<{ redirectUrl: string }>();
  const code = new URL(redirectUrl).searchParams.get("code");
  expect(code).toBeTruthy();
  return code!;
}

function exchange(fields: Record<string, string>) {
  return asWebApp("/internal/oauth/token", { method: "POST", body: fields });
}

async function tokenFor(
  request: OAuthAuthorizationRequest,
  verifier: string,
  permissions?: PermissionId[]
): Promise<string> {
  const code = await approvedCode(request, permissions);
  const response = await exchange({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    client_id: request.client_id!,
    redirect_uri: request.redirect_uri!,
    resource: RESOURCE,
  });
  expect(response.status).toBe(200);
  return (await response.json<{ access_token: string }>()).access_token;
}

/** Sign in as Claude with the given grant, returning the issued token. */
async function signIn(permissions: PermissionId[] = ["sessions.read"], client = CLAUDE) {
  const redirect = client === CLAUDE_CODE ? "http://127.0.0.1:43123/callback" : CLAUDE_CALLBACK;
  const { request, verifier } = await authorizationRequest({
    client_id: client,
    redirect_uri: redirect,
    scope: permissions.join(" "),
  });
  return tokenFor(request, verifier, permissions);
}

async function setPolicy(rules: Partial<PersonalAccessTokenPolicy>) {
  const current = await serviceFetch(`${BASE}/settings/personal-access-token-policy`, {
    as: ADMIN,
  });
  const { revision, ...stored } = await current.json<
    PersonalAccessTokenPolicy & { revision: number }
  >();
  const response = await serviceFetch(`${BASE}/settings/personal-access-token-policy`, {
    as: ADMIN,
    method: "PUT",
    headers: { "If-Match": `"pat-policy-${revision}"` },
    body: JSON.stringify({
      enabled: stored.enabled,
      mcpEnabled: stored.mcpEnabled,
      oauthClientIds: stored.oauthClientIds,
      maxLifetimeDays: stored.maxLifetimeDays,
      allowedPermissions: stored.allowedPermissions,
      ...rules,
    }),
  });
  expect(response.status).toBe(200);
}

async function fetchedClientDocuments(): Promise<string[]> {
  return (await fetch(`${TEST_CLIENT_ORIGIN}/__fixture/fetched`)).json();
}

/** A real MCP client on `/mcp` with the given token. */
async function connect(token: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
    fetch: (url, init) =>
      routeRequest(
        new Request(url, { ...init, signal: undefined }),
        deployed,
        createExecutionContext()
      ),
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "integration", version: "0" });
  await client.connect(transport);
  return client;
}

async function tokenRows(userId = OWNER) {
  const { results } = await env.DB.prepare(
    "SELECT id, name, oauth_client_id FROM personal_access_tokens WHERE user_id = ? ORDER BY created_at"
  )
    .bind(userId)
    .all<{ id: string; name: string; oauth_client_id: string | null }>();
  return results;
}

async function pastedToken(permissions: PermissionId[]): Promise<string> {
  const result = await new PersonalAccessTokenStore(env.DB).issue({
    userId: OWNER,
    name: "pasted",
    permissions,
    expiresAt: Date.now() + 60 * 60 * 1000,
    now: Date.now(),
    requestId: "integration",
  });
  if (result.kind !== "issued") throw new Error("token was not issued");
  return result.token.token;
}

beforeEach(async () => {
  await cleanD1Tables();
  await fetch(`${TEST_CLIENT_ORIGIN}/__fixture/reset`);
  // Seed the owner and administrator with their roles.
  await serviceFetch(`${BASE}/personal-access-tokens`, { as: { userId: OWNER, role: "owner" } });
  await serviceFetch(`${BASE}/settings/personal-access-token-policy`, { as: ADMIN });
});
afterEach(cleanD1Tables);

describe("OAuth metadata", () => {
  it("publishes the protected resource metadata for /mcp, pointing at the web app", async () => {
    const response = await controlPlane("/.well-known/oauth-protected-resource/mcp");
    expect(response.status).toBe(200);
    const metadata = await response.json<Record<string, unknown>>();
    expect(metadata).toEqual({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      bearer_methods_supported: ["header"],
      // The reads the MCP tools use, not every read a token could hold.
      scopes_supported: ["automations.read", "sessions.read", "skills.read"],
    });
    // Only reads: writing is asked for by step-up.
    expect(metadata.scopes_supported).not.toContain("sessions.create");
    expect(metadata.scopes_supported).not.toContain("offline_access");
  });

  it("serves the authorization server metadata to the web app", async () => {
    const response = await asWebApp("/internal/oauth/authorization-server-metadata");
    expect(response.status).toBe(200);
    const metadata = await response.json<Record<string, unknown>>();
    expect(metadata).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    });
    expect(metadata.scopes_supported).toContain("sessions.create");
    expect(metadata.scopes_supported).not.toContain("offline_access");
    expect(metadata).not.toHaveProperty("registration_endpoint");
    // Not callable by anyone but the web app.
    expect((await controlPlane("/internal/oauth/authorization-server-metadata")).status).toBe(401);
  });

  it("scopes the metadata to the policy's permission ceiling", async () => {
    await setPolicy({ allowedPermissions: ["sessions.read", "sessions.collaborate"] });
    const resource = await (
      await controlPlane("/.well-known/oauth-protected-resource/mcp")
    ).json<{ scopes_supported: string[] }>();
    expect(resource.scopes_supported).toEqual(["sessions.read"]);
    const server = await (
      await asWebApp("/internal/oauth/authorization-server-metadata")
    ).json<{ scopes_supported: string[] }>();
    expect(server.scopes_supported).toEqual(["sessions.collaborate", "sessions.read"].sort());
  });

  it("is absent without the deployment's public URLs", async () => {
    const unconfigured = { ...env, WORKER_URL: undefined };
    const response = await controlPlane(
      "/.well-known/oauth-protected-resource/mcp",
      {},
      unconfigured
    );
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: "OAuth sign-in is not available" });
    const unauthenticated = await controlPlane("/mcp", { method: "POST" }, unconfigured);
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.headers.get("WWW-Authenticate")).toBe('Bearer realm="open-inspect"');
  });

  it("challenges an unauthenticated /mcp request with the resource metadata and read scopes", async () => {
    const missing = await controlPlane("/mcp", { method: "POST", body: "{}" });
    expect(missing.status).toBe(401);
    const challenge = missing.headers.get("WWW-Authenticate")!;
    expect(challenge).toContain(
      `resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`
    );
    expect(challenge).toMatch(/scope="[^"]*sessions\.read[^"]*"/);
    expect(challenge).not.toContain("error=");

    const unknown = await controlPlane("/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer oi_pat_${"0".repeat(64)}` },
      body: "{}",
    });
    expect(unknown.status).toBe(401);
    expect(unknown.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
  });
});

describe("OAuth sign-in", () => {
  it("signs in, issues a token, and the token works at /mcp and against the API", async () => {
    const { sessionName } = await initSession({ userId: OWNER, title: "Signed in" });
    const { request, verifier } = await authorizationRequest();

    const consent = await check(request);
    expect(consent).toMatchObject({
      kind: "consent",
      client: { id: CLAUDE, host: "claude.ai" },
      redirect: { host: "claude.ai", loopback: false },
      requested: ["sessions.read"],
      maxLifetimeDays: 365,
    });
    if (consent.kind !== "consent") throw new Error("unreachable");
    expect(consent.grantable).toContain("sessions.create");
    const deny = new URL(consent.denyUrl);
    expect(`${deny.origin}${deny.pathname}`).toBe(CLAUDE_CALLBACK);
    expect(Object.fromEntries(deny.searchParams)).toEqual({
      error: "access_denied",
      state: "state-1",
      iss: ISSUER,
    });

    const approved = await approve(request, ["sessions.read"], 30);
    expect(approved.status).toBe(200);
    const { redirectUrl } = await approved.json<{ redirectUrl: string }>();
    const back = new URL(redirectUrl);
    expect(`${back.origin}${back.pathname}`).toBe(CLAUDE_CALLBACK);
    expect(back.searchParams.get("state")).toBe("state-1");
    expect(back.searchParams.get("iss")).toBe(ISSUER);
    const code = back.searchParams.get("code")!;
    // Only a hash of the code is kept.
    const stored = await env.DB.prepare("SELECT code_hash FROM oauth_authorization_codes").all();
    expect(JSON.stringify(stored.results)).not.toContain(code);

    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
      resource: RESOURCE,
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const token = await response.json<{
      access_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
      refresh_token?: string;
    }>();
    expect(token).toEqual({
      access_token: expect.stringMatching(/^oi_pat_[0-9a-f]{64}$/),
      token_type: "Bearer",
      expires_in: 30 * 24 * 60 * 60,
      scope: "sessions.read",
    });
    expect(token.refresh_token).toBeUndefined();
    // An ordinary token row, recorded as issued to the client.
    expect(await tokenRows()).toEqual([
      { id: expect.any(String), name: "Claude (claude.ai)", oauth_client_id: CLAUDE },
    ]);

    const client = await connect(token.access_token);
    const read = await client.callTool({
      name: "get_session",
      arguments: { session_id: sessionName },
    });
    expect(read.isError).toBeFalsy();
    await client.close();

    const direct = await controlPlane(`/sessions/${sessionName}`, {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    expect(direct.status).toBe(200);
  });

  it("accepts Claude Code's loopback redirect on any port, by 127.0.0.1 or localhost", async () => {
    for (const redirect of ["http://127.0.0.1:43123/callback", "http://localhost:8/callback"]) {
      const { request } = await authorizationRequest({
        client_id: CLAUDE_CODE,
        redirect_uri: redirect,
      });
      await expect(check(request)).resolves.toMatchObject({
        kind: "consent",
        client: { host: "claude.ai" },
        redirect: { loopback: true },
      });
    }
    // The path must still match.
    const { request } = await authorizationRequest({
      client_id: CLAUDE_CODE,
      redirect_uri: "http://127.0.0.1:43123/elsewhere",
    });
    await expect(check(request)).resolves.toMatchObject({
      kind: "error",
      code: "oauth_redirect_uri_invalid",
    });
  });

  it("refuses an exchange whose PKCE verifier does not match, and spends the code", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    const fields = {
      grant_type: "authorization_code",
      code,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    };

    const wrong = await exchange({ ...fields, code_verifier: (await pkce()).verifier });
    expect(wrong.status).toBe(400);
    await expect(wrong.json()).resolves.toMatchObject({ error: "invalid_grant" });
    // The right verifier is too late: the code was claimed by the first attempt.
    const late = await exchange({ ...fields, code_verifier: verifier });
    await expect(late.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("requires PKCE S256 on the authorization request, and says so to the client", async () => {
    for (const overrides of [
      { code_challenge: undefined },
      { code_challenge_method: "plain" },
      { code_challenge: "too-short" },
    ]) {
      const { request } = await authorizationRequest(overrides);
      const consent = await check(request);
      expect(consent.kind).toBe("redirect");
      if (consent.kind !== "redirect") continue;
      const back = new URL(consent.url);
      expect(back.searchParams.get("error")).toBe("invalid_request");
      expect(back.searchParams.get("iss")).toBe(ISSUER);
    }
  });

  it("sends a malformed request back to a verified client, naming the issuer", async () => {
    for (const [overrides, error] of [
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ resource: "https://elsewhere.test/mcp" }, "invalid_target"],
    ] as const) {
      const { request } = await authorizationRequest(overrides);
      const consent = await check(request);
      expect(consent.kind).toBe("redirect");
      if (consent.kind !== "redirect") continue;
      const back = new URL(consent.url);
      expect(`${back.origin}${back.pathname}`).toBe(CLAUDE_CALLBACK);
      expect(back.searchParams.get("error")).toBe(error);
      expect(back.searchParams.get("state")).toBe("state-1");
      expect(back.searchParams.get("iss")).toBe(ISSUER);
      expect((await approve(request)).status).toBe(400);
    }
    // A client that names no resource means the hosted MCP server.
    const { request } = await authorizationRequest({ resource: undefined });
    await expect(check(request)).resolves.toMatchObject({ kind: "consent" });
  });

  it("refuses an exchange for another resource than the code's", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
      resource: "https://elsewhere.test/mcp",
    });
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_target" });
    expect(await tokenRows()).toEqual([]);
  });

  it("refuses an exchange once the API policy has changed since approval", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    await setPolicy({ maxLifetimeDays: 7 });
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("issues nothing for a code replayed before its first exchange finished", async () => {
    const { request } = await authorizationRequest();
    const code = await approvedCode(request);
    const codes = new OAuthAuthorizationCodeStore(sqlDatabase(env.DB));
    const codeHash = await hashToken(code);
    const first = await codes.claim(codeHash, Date.now());
    if (first.kind !== "claimed") throw new Error("the code was not claimed");
    // The replay lands between the first exchange's claim and its issue.
    await expect(codes.claim(codeHash, Date.now())).resolves.toMatchObject({
      kind: "replayed",
      issuedTokenId: null,
    });
    const issued = await new PersonalAccessTokenStore(env.DB).issue({
      userId: OWNER,
      name: "late",
      permissions: first.code.permissions,
      expiresAt: Date.now() + 60_000,
      now: Date.now(),
      requestId: "integration",
      policyRevision: first.code.policyRevision,
      oauth: { clientId: CLAUDE, codeHash, expiredTokenIds: [] },
    });
    expect(issued.kind).toBe("code_unavailable");
    expect(await tokenRows()).toEqual([]);
  });

  it("refuses a redirect URI the client did not register, without redirecting to it", async () => {
    for (const redirect of [
      "https://evil.test/callback",
      `${CLAUDE_CALLBACK}?extra=1`,
      undefined,
    ]) {
      const { request } = await authorizationRequest({ redirect_uri: redirect });
      await expect(check(request)).resolves.toMatchObject({
        kind: "error",
        code: "oauth_redirect_uri_invalid",
      });
      expect((await approve(request)).status).toBe(400);
    }
    expect(await env.DB.prepare("SELECT 1 FROM oauth_authorization_codes").all()).toMatchObject({
      results: [],
    });
  });

  it("refuses a registered redirect URI on another origin than the client's", async () => {
    await setPolicy({ oauthClientIds: [TEST_CLIENT] });
    const { request } = await authorizationRequest({
      client_id: TEST_CLIENT,
      redirect_uri: "https://elsewhere.test/callback",
    });
    await expect(check(request)).resolves.toMatchObject({
      kind: "error",
      code: "oauth_redirect_uri_invalid",
    });
  });

  it("refuses an exchange with a different redirect URI or client than the code's", async () => {
    const { request, verifier } = await authorizationRequest();
    for (const changed of [
      { redirect_uri: "https://claude.ai/api/mcp/other" },
      { client_id: CLAUDE_CODE },
    ]) {
      const code = await approvedCode(request);
      const response = await exchange({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        client_id: CLAUDE,
        redirect_uri: CLAUDE_CALLBACK,
        ...changed,
      });
      await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    }
    expect(await tokenRows()).toEqual([]);
  });

  it("refuses a client the policy does not list, without fetching its document", async () => {
    const { request } = await authorizationRequest({
      client_id: TEST_CLIENT,
      redirect_uri: `${TEST_CLIENT_ORIGIN}/callback`,
    });
    await expect(check(request)).resolves.toMatchObject({
      kind: "error",
      code: "oauth_client_untrusted",
    });
    expect((await approve(request)).status).toBe(400);
    expect(await fetchedClientDocuments()).toEqual([]);

    // Once an administrator lists it, it signs in, identified by its host.
    await setPolicy({ oauthClientIds: [TEST_CLIENT] });
    await expect(check(request)).resolves.toMatchObject({
      kind: "consent",
      client: { id: TEST_CLIENT, host: "client.test", name: "Definitely Claude" },
    });
    // The document's own name is shown only beside the host it is served from.
    // Replacing the defaults removes Claude.
    await expect(check((await authorizationRequest()).request)).resolves.toMatchObject({
      kind: "error",
      code: "oauth_client_untrusted",
    });
  });

  it("refuses a listed client whose document is not valid", async () => {
    const documents = ["redirecting", "impostor", "oversized", "confidential", "missing"].map(
      (name) => `${TEST_CLIENT_ORIGIN}/${name}`
    );
    await setPolicy({ oauthClientIds: documents });
    for (const clientId of documents) {
      const { request } = await authorizationRequest({
        client_id: clientId,
        redirect_uri: `${TEST_CLIENT_ORIGIN}/callback`,
      });
      await expect(check(request), clientId).resolves.toMatchObject({
        kind: "error",
        code: "oauth_client_metadata_invalid",
      });
    }
    // A redirect is not followed.
    expect(await fetchedClientDocuments()).not.toContain(TEST_CLIENT);
  });

  it("revokes the issued token when its code is presented again", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    const fields = {
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    };
    const first = await exchange(fields);
    const { access_token: token } = await first.json<{ access_token: string }>();
    expect(
      (await controlPlane("/sessions", { headers: { Authorization: `Bearer ${token}` } })).status
    ).toBe(200);

    const replay = await exchange(fields);
    expect(replay.status).toBe(400);
    await expect(replay.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
    expect(
      (await controlPlane("/sessions", { headers: { Authorization: `Bearer ${token}` } })).status
    ).toBe(401);
    // Recorded as a replay, not as the owner revoking it.
    const revoked = await env.DB.prepare(
      `SELECT reason_code FROM authorization_audit_events
        WHERE action = 'personal_access_token.revoked'`
    ).all<{ reason_code: string }>();
    expect(revoked.results).toEqual([{ reason_code: "oauth_code_replayed" }]);
  });

  it("refuses a malformed verifier even when it answers the challenge", async () => {
    const verifier = "too-short";
    const { request } = await authorizationRequest({
      code_challenge: await s256CodeChallenge(verifier),
    });
    const code = await approvedCode(request);
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("refuses the exchange once the deployment's URLs are gone", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    const headers = await serviceRequestHeaders(`${BASE}/internal/oauth/token`, {
      method: "POST",
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        client_id: CLAUDE,
        redirect_uri: CLAUDE_CALLBACK,
      }),
    });
    const response = await controlPlane(
      "/internal/oauth/token",
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          code_verifier: verifier,
          client_id: CLAUDE,
          redirect_uri: CLAUDE_CALLBACK,
        }),
      },
      { ...env, WORKER_URL: undefined }
    );
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("prunes the client's expired tokens, so they never fill the cap", async () => {
    const expired = await signIn(["sessions.read"]);
    const [expiredRow] = await tokenRows();
    await env.DB.prepare("UPDATE personal_access_tokens SET expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1, expiredRow.id)
      .run();
    // Expired tokens of another client, and one made in Settings, are not this client's to prune.
    await signIn(["sessions.read"], CLAUDE_CODE);
    await pastedToken(["sessions.read"]);
    const [, otherClient, settings] = await tokenRows();
    await env.DB.prepare("UPDATE personal_access_tokens SET expires_at = ? WHERE id IN (?, ?)")
      .bind(Date.now() - 1, otherClient.id, settings.id)
      .run();
    // The user now holds 50 tokens: at the cap, unless this client's expired one is not counted.
    for (let index = 0; index < 47; index++) await pastedToken(["sessions.read"]);

    const fresh = await signIn(["sessions.read"]);
    const rows = await tokenRows();
    expect(rows).toHaveLength(50);
    expect(rows.map((row) => row.id)).not.toContain(expiredRow.id);
    expect(rows.map((row) => row.id)).toEqual(
      expect.arrayContaining([otherClient.id, settings.id])
    );
    const pruned = await env.DB.prepare(
      `SELECT resource_id, reason_code FROM authorization_audit_events
        WHERE action = 'personal_access_token.revoked'`
    ).all();
    expect(pruned.results).toEqual([
      { resource_id: expiredRow.id, reason_code: "oauth_expired_pruned" },
    ]);
    const live = async (token: string) =>
      (await controlPlane("/sessions", { headers: { Authorization: `Bearer ${token}` } })).status;
    expect(await live(expired)).toBe(401);
    expect(await live(fresh)).toBe(200);
  });

  it("refuses an expired code", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    await env.DB.prepare("UPDATE oauth_authorization_codes SET expires_at = ?")
      .bind(Date.now() - 1)
      .run();
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("caps the lifetime chosen at consent at the policy's maximum", async () => {
    await setPolicy({ maxLifetimeDays: 7 });
    const { request, verifier } = await authorizationRequest();
    await expect(check(request)).resolves.toMatchObject({ kind: "consent", maxLifetimeDays: 7 });

    const tooLong = await approve(request, ["sessions.read"], 30);
    expect(tooLong.status).toBe(400);
    await expect(tooLong.json()).resolves.toMatchObject({ code: "lifetime_exceeds_policy" });

    const code = await approvedCode(request, ["sessions.read"], 7);
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(response.json()).resolves.toMatchObject({ expires_in: 7 * 24 * 60 * 60 });
  });

  it("checks the grant when the user approves, so refusals show on the consent page", async () => {
    const { request } = await authorizationRequest();
    const withheld = await approve(request, ["workspace.members.manage"]);
    expect(withheld.status).toBe(400);
    await expect(withheld.json()).resolves.toMatchObject({ code: "permission_not_grantable" });
    const missingPrerequisite = await approve(request, ["sessions.collaborate"]);
    await expect(missingPrerequisite.json()).resolves.toMatchObject({
      code: "permission_prerequisite_missing",
    });

    // At the per-user cap, approving says so rather than leaving the client an invalid_grant.
    for (let index = 0; index < 50; index++) await pastedToken(["sessions.read"]);
    const capped = await approve(request);
    expect(capped.status).toBe(409);
    await expect(capped.json()).resolves.toMatchObject({
      code: "personal_access_token_limit_reached",
    });
  });

  it("refuses the exchange once the user is suspended", async () => {
    const { request, verifier } = await authorizationRequest();
    const code = await approvedCode(request);
    await env.DB.prepare("UPDATE users SET suspended_at = ? WHERE id = ?")
      .bind(Date.now(), OWNER)
      .run();
    const response = await exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
    expect(await tokenRows()).toEqual([]);
  });

  it("refuses a token request that is not an authorization code exchange", async () => {
    const refresh = await exchange({ grant_type: "refresh_token", refresh_token: "x" });
    await expect(refresh.json()).resolves.toMatchObject({ error: "unsupported_grant_type" });
    const incomplete = await exchange({ grant_type: "authorization_code", code: "x" });
    await expect(incomplete.json()).resolves.toMatchObject({ error: "invalid_request" });
    const unknown = await exchange({
      grant_type: "authorization_code",
      code: "unknown",
      code_verifier: (await pkce()).verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(unknown.json()).resolves.toMatchObject({ error: "invalid_grant" });
  });
});

describe("OAuth and the API policy's MCP switch", () => {
  it("stops sign-in and every token issued through it while MCP clients are off", async () => {
    const oauthToken = await signIn(["sessions.read"]);
    const pasted = await pastedToken(["sessions.read"]);
    const { request, verifier } = await authorizationRequest();
    const pendingCode = await approvedCode(request);

    await setPolicy({ mcpEnabled: false });
    expect((await controlPlane("/.well-known/oauth-protected-resource/mcp")).status).toBe(404);
    expect((await asWebApp("/internal/oauth/authorization-server-metadata")).status).toBe(404);
    await expect(check(request)).resolves.toMatchObject({
      kind: "error",
      code: "oauth_unavailable",
    });
    const exchanged = await exchange({
      grant_type: "authorization_code",
      code: pendingCode,
      code_verifier: verifier,
      client_id: CLAUDE,
      redirect_uri: CLAUDE_CALLBACK,
    });
    await expect(exchanged.json()).resolves.toMatchObject({ error: "invalid_grant" });

    const api = (token: string) =>
      controlPlane("/sessions", { headers: { Authorization: `Bearer ${token}` } });
    // A token issued to an app stops everywhere; one made in Settings keeps working with the API.
    expect((await api(oauthToken)).status).toBe(401);
    expect((await api(pasted)).status).toBe(200);

    await setPolicy({ mcpEnabled: true });
    expect((await api(oauthToken)).status).toBe(200);
  });

  it("stops a client's tokens once the API policy no longer lists it", async () => {
    const claude = await signIn(["sessions.read"]);
    const claudeCode = await signIn(["sessions.read"], CLAUDE_CODE);
    const live = async (token: string) =>
      (await controlPlane("/sessions", { headers: { Authorization: `Bearer ${token}` } })).status;

    await setPolicy({ oauthClientIds: [CLAUDE_CODE] });
    expect(await live(claude)).toBe(401);
    expect(await live(claudeCode)).toBe(200);
    await setPolicy({ oauthClientIds: null });
    expect(await live(claude)).toBe(200);
  });

  it("explains on the consent page that tokens are off", async () => {
    await setPolicy({ enabled: false });
    await expect(check((await authorizationRequest()).request)).resolves.toMatchObject({
      kind: "error",
      code: "personal_access_tokens_disabled",
    });
  });
});
