import type { TierDef } from "../policy/loader.js";

export type QuotaState = {
  calls_total: number;
  calls_by_tool: Map<string, number>;
  bytes_returned_total: number;
  createdAt: number; // unix ms — used for TTL cleanup
};

// Quota state persists across multiple HTTP calls sharing the same request_id.
// This allows per-LLM-turn quotas (one turn = many /invoke-tool calls, same request_id).
// Entries older than QUOTA_TTL_MS are pruned lazily on each get().
const QUOTA_TTL_MS = 30 * 60 * 1000; // 30 minutes

export class QuotaTracker {
  private state = new Map<string, QuotaState>();

  get(requestId: string): QuotaState {
    this.pruneExpired();

    let s = this.state.get(requestId);
    if (!s) {
      s = { calls_total: 0, calls_by_tool: new Map(), bytes_returned_total: 0, createdAt: Date.now() };
      this.state.set(requestId, s);
    }
    return s;
  }

  private pruneExpired(): void {
    const cutoff = Date.now() - QUOTA_TTL_MS;
    for (const [id, entry] of this.state) {
      if (entry.createdAt < cutoff) this.state.delete(id);
    }
  }
}

/**
 * Check + increment is fully synchronous — no await between read and write.
 * This prevents races even under concurrent async handlers sharing the same tracker.
 */
export function applyQuotasOrThrow(
  requestId: string,
  toolName: string,
  tier: TierDef,
  quota: QuotaTracker
): void {
  const q = tier.quotas ?? {};
  const maxTotal = q.max_calls_per_request ?? Infinity;
  const maxPerTool = q.max_calls_per_tool ?? Infinity;

  // T0_DENY shortcut — max_calls_per_request: 0
  if (maxTotal === 0) {
    throw new Error("Quota: tier allows 0 calls (T0_DENY)");
  }

  const s = quota.get(requestId);
  const curTool = s.calls_by_tool.get(toolName) ?? 0;

  // SYNCHRONOUS: check then mutate, no await in between
  if (s.calls_total + 1 > maxTotal) throw new Error("Quota exceeded: max_calls_per_request");
  if (curTool + 1 > maxPerTool) throw new Error("Quota exceeded: max_calls_per_tool");

  s.calls_total += 1;
  s.calls_by_tool.set(toolName, curTool + 1);
}

export function trackResponseBytes(
  requestId: string,
  bytes: number,
  tier: TierDef,
  quota: QuotaTracker
): void {
  const max = tier.quotas?.max_response_bytes ?? Infinity;
  const s = quota.get(requestId);
  s.bytes_returned_total += bytes;
  if (s.bytes_returned_total > max) {
    throw new Error("Quota exceeded: max_response_bytes");
  }
}
