/**
 * The hosted MCP server's URL, derived from the control plane's public WebSocket URL: the same
 * host, over HTTP(S), at `/mcp`.
 */
export function hostedMcpUrl(webSocketUrl: string): string {
  const url = new URL(webSocketUrl);
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  return `${url.origin}/mcp`;
}

export const HOSTED_MCP_URL = hostedMcpUrl(process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8787");
