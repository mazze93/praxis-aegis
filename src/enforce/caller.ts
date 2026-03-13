import crypto from "node:crypto";
import type { TierDef } from "../policy/loader.js";

export type CallerPayload = {
  request_id: string;
  identity: string;
  caller_type: Caller["type"];
  tool_name: string;
  tool_id?: string;
  iat: number;
  exp: number;
};

export type Caller = {
  type: "model" | "code_execution";
  tool_id?: string;
  signed_token?: string;
};

/**
 * Verifies an HMAC-signed caller token.
 * Token format: base64url(JSON payload) + "." + base64url(HMAC-SHA256 signature)
 * Payload is validated for: valid JSON, request_id match, and expiry.
 */
export function verifySignedCallerToken(
  token: string | undefined,
  secret: string,
  expected: {
    requestId: string;
    identity: string;
    callerType: Caller["type"];
    toolName: string;
    toolId?: string;
  }
): { ok: boolean; reason?: string } {
  if (!token) return { ok: false, reason: "missing token" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed token" };

  const [payloadB64, sigB64] = parts as [string, string];

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64url");

  const providedSig = Buffer.from(sigB64, "base64url");
  const expectedSig = Buffer.from(expectedSignature, "base64url");
  if (providedSig.length !== expectedSig.length) {
    return { ok: false, reason: "signature invalid" };
  }

  const sigOk = crypto.timingSafeEqual(providedSig, expectedSig);
  if (!sigOk) return { ok: false, reason: "signature invalid" };

  let payload: CallerPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as CallerPayload;
  } catch {
    return { ok: false, reason: "payload not valid JSON" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) return { ok: false, reason: "token expired" };
  if (payload.request_id !== expected.requestId) {
    return { ok: false, reason: "request_id mismatch (replay prevention)" };
  }
  if (payload.identity !== expected.identity) {
    return { ok: false, reason: "identity mismatch" };
  }
  if (payload.caller_type !== expected.callerType) {
    return { ok: false, reason: "caller_type mismatch" };
  }
  if (payload.tool_name !== expected.toolName) {
    return { ok: false, reason: "tool_name mismatch" };
  }
  if ((payload.tool_id ?? undefined) !== (expected.toolId ?? undefined)) {
    return { ok: false, reason: "tool_id mismatch" };
  }

  return { ok: true };
}

export function callerVerificationOrThrow(
  caller: Caller | undefined,
  callersRule: TierDef["callers"],
  hmacSecret: string,
  expected: {
    requestId: string;
    identity: string;
    toolName: string;
  }
): void {
  const allowCallers = callersRule?.allow_callers ?? [];
  const requireSigned = callersRule?.require_signed_caller ?? false;

  const c: Caller = caller ?? { type: "model" };

  const allowed = allowCallers.some((x) => x.type === c.type);
  if (!allowed) throw new Error(`Caller type "${c.type}" not permitted by this tier`);

  if (c.type === "code_execution" && !c.tool_id) {
    throw new Error("code_execution caller must include tool_id");
  }

  if (requireSigned) {
    const result = verifySignedCallerToken(c.signed_token, hmacSecret, {
      requestId: expected.requestId,
      identity: expected.identity,
      callerType: c.type,
      toolName: expected.toolName,
      toolId: c.tool_id,
    });
    if (!result.ok) throw new Error(`Caller token verification failed: ${result.reason}`);
  }

  if (callersRule?.require_human_approval) {
    throw new Error(
      "Human approval required for this tier. " +
        "Use POST /approve/:request_id to issue a grant token (not yet implemented)."
    );
  }
}

/** Build a signed caller token for use in tests or by trusted orchestrators. */
export function buildCallerToken(
  payload: CallerPayload,
  secret: string
): string {
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64url");
  return `${payloadB64}.${sig}`;
}
