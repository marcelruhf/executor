import { describe, expect, it } from "@effect/vitest";

import { authToolFailure } from "./auth-tool-failure";
import { detectInsufficientScope } from "./insufficient-scope";

describe("detectInsufficientScope", () => {
  it("detects Google's ErrorInfo reason nested in an error body", () => {
    const body = {
      error: {
        code: 403,
        message: "Request had insufficient authentication scopes.",
        status: "PERMISSION_DENIED",
        details: [
          {
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
            domain: "googleapis.com",
            metadata: { service: "drive.googleapis.com" },
          },
        ],
      },
    };
    expect(detectInsufficientScope({ body })).toEqual({ requiredScopes: [] });
  });

  it("detects the RFC 6750 error body", () => {
    expect(detectInsufficientScope({ body: { error: "insufficient_scope" } })).toEqual({
      requiredScopes: [],
    });
  });

  it("reads required scopes from a WWW-Authenticate challenge", () => {
    expect(
      detectInsufficientScope({
        body: null,
        headers: {
          "www-authenticate":
            'Bearer realm="example", error="insufficient_scope", scope="files.read files.meta"',
        },
      }),
    ).toEqual({ requiredScopes: ["files.read", "files.meta"] });
  });

  it("detects the signal inside a plain-text body", () => {
    expect(detectInsufficientScope({ body: '{"error":"insufficient_scope"}' })).toEqual({
      requiredScopes: [],
    });
  });

  it("returns null for an ordinary 403 body", () => {
    expect(
      detectInsufficientScope({
        body: { error: { status: "PERMISSION_DENIED", message: "Caller lacks permission" } },
        headers: { "www-authenticate": 'Bearer realm="example", error="invalid_token"' },
      }),
    ).toBeNull();
  });

  it("returns null for empty input", () => {
    expect(detectInsufficientScope({})).toBeNull();
  });
});

describe("authToolFailure recovery for oauth_scope_insufficient", () => {
  const recoveryOf = (result: ReturnType<typeof authToolFailure>) => {
    const details = (result as { error: { details: { recovery: Record<string, string> } } }).error
      .details;
    return details.recovery;
  };

  it("omits the oauth.start hint, which would re-run the identical grant", () => {
    const recovery = recoveryOf(
      authToolFailure({ code: "oauth_scope_insufficient", message: "scope shortfall" }),
    );
    expect(recovery.startOAuthTool).toBeUndefined();
    expect(recovery.oauthInstructions).toBeUndefined();
    expect(recovery.scopeInstructions).toContain("does not cover the scope");
    expect(recovery.listConnectionsTool).toBe("executor.coreTools.connections.list");
  });

  it("keeps the full recovery block for connection_rejected", () => {
    const recovery = recoveryOf(
      authToolFailure({ code: "connection_rejected", message: "rejected" }),
    );
    expect(recovery.startOAuthTool).toBe("executor.coreTools.oauth.start");
    expect(recovery.oauthInstructions).toBeDefined();
  });
});
