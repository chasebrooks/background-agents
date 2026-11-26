import { describe, expect, it } from "vitest";
import {
  OAUTH_AUTHORIZATION_REQUEST_PARAMETERS,
  oauthApprovalRequestSchema,
  oauthAuthorizationRequestSchema,
  oauthConsentResponseSchema,
} from "./oauth";

describe("OAuth sign-in contract", () => {
  it("names the authorization request parameters the consent page forwards", () => {
    expect(OAUTH_AUTHORIZATION_REQUEST_PARAMETERS).toEqual([
      "response_type",
      "client_id",
      "redirect_uri",
      "state",
      "scope",
      "code_challenge",
      "code_challenge_method",
      "resource",
    ]);
  });

  it("refuses an authorization request with an unknown or over-long parameter", () => {
    expect(oauthAuthorizationRequestSchema.safeParse({ prompt: "consent" }).success).toBe(false);
    expect(oauthAuthorizationRequestSchema.safeParse({ state: "x".repeat(4097) }).success).toBe(
      false
    );
  });

  it("requires an approval to grant something for at least a day", () => {
    expect(
      oauthApprovalRequestSchema.safeParse({ request: {}, permissions: [], expiresInDays: 30 })
        .success
    ).toBe(false);
    expect(
      oauthApprovalRequestSchema.safeParse({
        request: {},
        permissions: ["sessions.read"],
        expiresInDays: 0,
      }).success
    ).toBe(false);
  });

  it("parses each consent outcome", () => {
    for (const outcome of [
      { kind: "redirect", url: "https://client.example/cb?error=invalid_request" },
      { kind: "error", code: "oauth_client_untrusted", message: "Not allowed" },
    ]) {
      expect(oauthConsentResponseSchema.parse(outcome)).toEqual(outcome);
    }
  });
});
