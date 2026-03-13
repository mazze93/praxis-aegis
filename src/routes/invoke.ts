import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { requireSession } from "../middleware/requireSession.js";
import { resolvePolicySetId, resolveTierId } from "../policy/loader.js";
import { resolveEffectiveTier } from "../policy/resolve.js";
import { QuotaTracker, applyQuotasOrThrow, trackResponseBytes } from "../enforce/quota.js";
import { callerVerificationOrThrow, type Caller } from "../enforce/caller.js";
import { toolAllowedOrThrow } from "../enforce/tier.js";
import { redactOutput } from "../enforce/redact.js";
import { config } from "../config.js";
import { ToolBackendError } from "../backends/http.js";
import type { TierDef } from "../policy/loader.js";
import type { ToolInvocationContext } from "../backends/registry.js";

const invocationSchema = z.object({
  request_id: z.string().min(1).max(128),
  tool_name: z.string().min(1).max(128),
  input: z.unknown(),
  caller: z
    .object({
      type: z.enum(["model", "code_execution"]),
      tool_id: z.string().optional(),
      signed_token: z.string().optional(),
    })
    .strict()
    .optional(),
  meta: z
    .object({
    // identity can be overridden here, but MUST match the session identity
      identity: z.string().min(1).max(64),
      trigger: z.enum(["research", "ops", "write", "admin"]),
    })
    .strict(),
}).strict();

function sanitizeErrorForCaller(err: unknown, tier: TierDef | undefined): string {
  if (err instanceof ToolBackendError) {
    return err.safeMessage;
  }

  const fallback = "Request denied by policy";
  const redactMessage = (message: string): string => {
    if (!tier) return fallback;

    try {
      return redactOutput(message, tier.redaction);
    } catch {
      return fallback;
    }
  };

  if (err instanceof Error) {
    return redactMessage(err.message);
  }

  return redactMessage(String(err));
}

export function createInvokeRouter(
  getPolicy: () => import("../policy/loader.js").PolicyDoc,
  quota: QuotaTracker,
  callToolBackend: (
    toolName: string,
    input: unknown,
    context: ToolInvocationContext
  ) => Promise<unknown>
) {
  const router = Router();

  router.post("/", requireSession, async (req: Request, res: Response) => {
    const parsed = invocationSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ ok: false, error: parsed.error.flatten() });
      return;
    }

    const inv = parsed.data;
    const sessionIdentity = req.session?.identity;

    // Identity in the request must match the authenticated session identity.
    // This prevents a model from escalating by requesting a different identity.
    if (inv.meta.identity !== sessionIdentity) {
      res.status(403).json({
        ok: false,
        error: `Identity mismatch: session is "${sessionIdentity}", request claims "${inv.meta.identity}"`,
      });
      return;
    }

    try {
      const policy = getPolicy();

      const policySetId = resolvePolicySetId(policy, inv.meta.identity);
      const baseTierId = resolveTierId(policy, policySetId, inv.meta.identity, inv.meta.trigger);
      const { tierId, tier } = resolveEffectiveTier(policy, baseTierId, inv.tool_name);

      // 1) Caller verification
      callerVerificationOrThrow(
        inv.caller as Caller | undefined,
        tier.callers,
        config.CALLER_HMAC_SECRET,
        {
          requestId: inv.request_id,
          identity: inv.meta.identity,
          toolName: inv.tool_name,
        }
      );

      // 2) Tool allow/deny
      toolAllowedOrThrow(inv.tool_name, tier);

      // 3) Quotas — SYNCHRONOUS check+increment before any await
      applyQuotasOrThrow(inv.request_id, inv.tool_name, tier, quota);

      // 4) Call backend tool
      const toolResult = await callToolBackend(inv.tool_name, inv.input, {
        requestId: inv.request_id,
        identity: inv.meta.identity,
        policySetId,
        tierId,
        callerType: (inv.caller?.type ?? "model"),
      });

      const rawText =
        typeof toolResult === "string" ? toolResult : JSON.stringify(toolResult);

      // 5) Track bytes + redact before returning to caller
      trackResponseBytes(inv.request_id, Buffer.byteLength(rawText, "utf8"), tier, quota);
      const safeText = redactOutput(rawText, tier.redaction);

      res.json({
        ok: true,
        policy: { policy_set_id: policySetId, tier_id: tierId },
        tool_name: inv.tool_name,
        content: safeText,
      });
    } catch (err: unknown) {
      if (err instanceof ToolBackendError) {
        console.error(
          `[praxis-aegis] backend failure request_id=${inv.request_id} tool=${inv.tool_name} detail=${err.internalDetail ?? "n/a"}`
        );
      }

      const policy = getPolicy();
      let tierForResponse: TierDef | undefined;
      try {
        const policySetId = resolvePolicySetId(policy, inv.meta.identity);
        const baseTierId = resolveTierId(policy, policySetId, inv.meta.identity, inv.meta.trigger);
        tierForResponse = resolveEffectiveTier(policy, baseTierId, inv.tool_name).tier;
      } catch {
        tierForResponse = undefined;
      }

      const safeMessage = sanitizeErrorForCaller(err, tierForResponse);
      const statusCode = err instanceof ToolBackendError ? err.statusCode : 403;
      res.status(statusCode).json({ ok: false, error: safeMessage });
    }
  });

  return router;
}
