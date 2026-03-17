import crypto from "node:crypto";

export type BackendAssertionPayload = {
  aud: string;
  iss: string;
  request_id: string;
  identity: string;
  policy_set_id: string;
  tier_id: string;
  caller_type: "model" | "code_execution";
  tool_name: string;
  iat: number;
  exp: number;
};

export function buildBackendAssertion(
  payload: BackendAssertionPayload,
  secret: string
): string {
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64url");
  return `${payloadB64}.${sig}`;
}

export function verifyBackendAssertion(
  token: string | undefined,
  secret: string,
  expected: {
    audience: string;
    toolName: string;
  }
): { ok: boolean; reason?: string; payload?: BackendAssertionPayload } {
  if (!token) return { ok: false, reason: "missing assertion" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed assertion" };

  const [payloadB64, sigB64] = parts as [string, string];
  const expectedSig = crypto
    .createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64url");

  const providedSig = Buffer.from(sigB64, "base64url");
  const expectedSigBytes = Buffer.from(expectedSig, "base64url");
  if (providedSig.length !== expectedSigBytes.length) {
    return { ok: false, reason: "signature invalid" };
  }
  if (!crypto.timingSafeEqual(providedSig, expectedSigBytes)) {
    return { ok: false, reason: "signature invalid" };
  }

  let payload: BackendAssertionPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as BackendAssertionPayload;
  } catch {
    return { ok: false, reason: "payload not valid JSON" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) return { ok: false, reason: "assertion expired" };
  if (payload.aud !== expected.audience) return { ok: false, reason: "audience mismatch" };
  if (payload.tool_name !== expected.toolName) return { ok: false, reason: "tool_name mismatch" };

  return { ok: true, payload };
}
