/**
 * The hosted MCP server at `/mcp`.
 *
 * An MCP client connects with a personal access token as its bearer credential. The route itself
 * grants nothing: it checks the API policy's MCP switch, refuses browser origins it does not
 * know, and confirms the token is live, then serves the MCP exchange. Every tool call becomes a
 * request to the control plane's own router, made in-process and carrying the same token, so
 * the route the tool calls admits it, narrows it to its grant, and audits it exactly as it would
 * a direct API call. A tool can therefore do nothing the token could not do without MCP.
 *
 * Stateless: each request is served by a fresh MCP server instance, nothing is kept between
 * requests, and GET and DELETE (2025-era session operations) are answered `405`.
 */

import { Hono } from "hono";
import { SERVICE_SIGNATURE_HEADER } from "@open-inspect/shared/service-auth";
import { createMcpHandler, originValidationResponse } from "@modelcontextprotocol/server";
import { authenticate, isAuthError } from "../auth/authenticate";
import { readPersonalAccessToken } from "../auth/personal-access-token";
import { PersonalAccessTokenPolicyStore } from "../db/personal-access-token-policy";
import { error } from "../http/responses";
import { createLogger } from "../logger";
import { ControlPlaneClient, type ControlPlaneFetch } from "../mcp-tools/client";
import { createHostedMcpServer } from "../mcp-tools/server";
import { admit, dispatch } from "../routing/admit";
import type { ControlPlaneHonoEnv } from "../routing/hono-env";
import type { Env } from "../types";
import {
  NO_AUTHORIZATION,
  SCM_AGNOSTIC_HANDLER_AUTHENTICATED_ROUTE,
  type RequestContext,
} from "./shared";

const logger = createLogger("hosted-mcp");

/** The path the hosted MCP server is served at. */
const HOSTED_MCP_PATH = "/mcp";

/**
 * Largest MCP request body accepted. A tool's arguments are a prompt (capped well below this) or
 * a handful of identifiers, so anything larger is refused before it is parsed.
 */
export const HOSTED_MCP_MAX_REQUEST_BODY_BYTES = 1024 * 1024;

/**
 * Hostnames a browser-originated request may come from: the deployment's own web app and control
 * plane. A request without an `Origin` header (every non-browser client) is not affected.
 */
function allowedOriginHostnames(env: Env): string[] {
  const hostnames: string[] = [];
  for (const value of [env.WEB_APP_URL, env.WORKER_URL]) {
    if (!value) continue;
    try {
      hostnames.push(new URL(value).hostname);
    } catch {
      // A malformed URL allows nothing; the setting is validated where it is used for links.
    }
  }
  return hostnames;
}

function unauthorized(message: string): Response {
  const response = error(message, 401);
  response.headers.set("WWW-Authenticate", 'Bearer realm="open-inspect"');
  return response;
}

/**
 * Serve tool calls through the control plane's own router, under the MCP request's trace so their
 * logs and audit events correlate with it. A tool only ever calls API paths, so a request back to
 * this route would mean a tool was given a path it should never build.
 */
function routerTransport(inProcessFetch: ControlPlaneFetch, traceId: string): ControlPlaneFetch {
  return (request) => {
    if (new URL(request.url).pathname === HOSTED_MCP_PATH) {
      return Promise.resolve(error("Not found", 404));
    }
    const traced = new Request(request);
    traced.headers.set("x-trace-id", traceId);
    return inProcessFetch(traced);
  };
}

async function serveMcp(
  request: Request,
  env: Env,
  ctx: RequestContext,
  inProcessFetch: ControlPlaneFetch
): Promise<Response> {
  // Off answers as though the route did not exist, before anything about the caller is checked.
  const policy = await new PersonalAccessTokenPolicyStore(ctx.db).get();
  if (!policy.mcpEnabled) return error("Not found", 404);

  const rejectedOrigin = originValidationResponse(request, allowedOriginHostnames(env));
  if (rejectedOrigin) return rejectedOrigin;

  // Only a personal access token: a service signature acts for a service, not for one person.
  const token = readPersonalAccessToken(request.headers);
  if (token === null || request.headers.has(SERVICE_SIGNATURE_HEADER)) {
    return unauthorized("A personal access token is required");
  }
  // Checked here as well as by every route a tool calls, so a revoked or expired token is told so
  // before the client lists tools it could not call.
  const auth = await authenticate(request, env, ctx);
  if (isAuthError(auth)) {
    return auth.status === 401 ? unauthorized(auth.reason) : error(auth.reason, auth.status);
  }

  const client = new ControlPlaneClient({
    baseUrl: new URL(request.url).origin,
    token,
    fetch: routerTransport(inProcessFetch, ctx.trace_id),
  });
  const handler = createMcpHandler(() => createHostedMcpServer(client), {
    legacy: "stateless",
    // No tool streams progress, so a 2026-07-28 exchange is one JSON body. (2025-era requests are
    // answered as a short event stream that ends with the result.)
    responseMode: "json",
    maxRequestBodySize: HOSTED_MCP_MAX_REQUEST_BODY_BYTES,
    onerror: (cause) => {
      // The message only: tool arguments can hold prompts and secrets, and are never logged.
      logger.warn("MCP exchange failed", {
        event: "hosted_mcp.exchange_failed",
        error_message: cause.message,
        request_id: ctx.request_id,
        trace_id: ctx.trace_id,
      });
    },
  });
  try {
    return await handler.fetch(request);
  } finally {
    await handler.close();
  }
}

/**
 * The route authenticates in its handler rather than in admission: it acts for no one itself, and
 * each tool call is admitted by the route it reaches.
 */
const HOSTED_MCP_ROUTE = {
  ...SCM_AGNOSTIC_HANDLER_AUTHENTICATED_ROUTE,
  authorization: NO_AUTHORIZATION,
  cacheControl: "no-store",
} as const;

export const hostedMcpRoutes = new Hono<ControlPlaneHonoEnv>();

for (const method of ["post", "get", "delete"] as const) {
  hostedMcpRoutes[method](HOSTED_MCP_PATH, admit(HOSTED_MCP_ROUTE), (c) =>
    dispatch(c, (request, env, _params, ctx) => serveMcp(request, env, ctx, c.var.inProcessFetch))
  );
}
