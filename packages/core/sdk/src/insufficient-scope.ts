// Detecting a scope-insufficient upstream rejection. A 403 that means "this
// grant does not cover that operation" is unfixable by re-running the same
// OAuth flow, so it must not be labelled connection_rejected (whose recovery
// tells the agent to re-authenticate). Providers signal it two ways:
//
//   - RFC 6750: a `WWW-Authenticate: Bearer error="insufficient_scope"
//     scope="..."` challenge header (the `scope` attribute names what the
//     request needed).
//   - Google (google.rpc.ErrorInfo): a JSON body whose error details carry
//     `reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT"`.
//   - Generic OAuth JSON: `{ "error": "insufficient_scope" }` (RFC 6750 §3.1
//     as a body, which some providers emit instead of the header).
//
// A miss is benign: the failure stays on the existing connection_rejected
// path. Detection never throws and never trusts shape beyond what it reads.

export type InsufficientScopeDetection = {
  /** Scopes the upstream named as required, when it named any (RFC 6750's
   *  `scope` attribute). Empty when the provider only signalled the class of
   *  failure (Google's ErrorInfo does not carry the missing scope). */
  readonly requiredScopes: readonly string[];
};

const MAX_DEPTH = 8;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** RFC 6750 §3: `Bearer error="insufficient_scope", scope="a b"`. */
const detectFromChallenge = (header: string): InsufficientScopeDetection | null => {
  if (!/error\s*=\s*"?insufficient_scope"?/i.test(header)) return null;
  const scope = /scope\s*=\s*"([^"]*)"/i.exec(header)?.[1];
  return { requiredScopes: scope ? scope.split(/\s+/).filter(Boolean) : [] };
};

const detectFromBody = (body: unknown, depth: number): boolean => {
  if (depth > MAX_DEPTH) return false;
  if (typeof body === "string") {
    // Bounded containment check for text bodies (some providers send the
    // OAuth error object as text/plain, and MCP transports surface only the
    // response text inside an error message).
    return body.includes("insufficient_scope") || body.includes("ACCESS_TOKEN_SCOPE_INSUFFICIENT");
  }
  if (Array.isArray(body)) {
    return body.some((item) => detectFromBody(item, depth + 1));
  }
  if (!isRecord(body)) return false;
  if (body.error === "insufficient_scope") return true;
  if (body.reason === "ACCESS_TOKEN_SCOPE_INSUFFICIENT") return true;
  return Object.values(body).some((value) => detectFromBody(value, depth + 1));
};

/** Inspect an upstream 401/403's body and headers for a scope-insufficiency
 *  signal. Returns `null` when nothing matches, so callers fall through to
 *  their existing classification. */
export const detectInsufficientScope = (input: {
  readonly body?: unknown;
  readonly headers?: Record<string, string>;
}): InsufficientScopeDetection | null => {
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    if (name.toLowerCase() !== "www-authenticate") continue;
    const detected = detectFromChallenge(value);
    if (detected) return detected;
  }
  return detectFromBody(input.body, 0) ? { requiredScopes: [] } : null;
};
