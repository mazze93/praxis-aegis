import fs from "node:fs";
import yaml from "yaml";
import { buildPolicyRegExp } from "./regex.js";

export type PolicyDoc = {
	version: number;
	policy_sets: Array<{ id: string; label: string }>;
	identities: Record<string, { label: string; default_policy_set: string }>;
	triggers: Record<string, { label: string }>;
	tiers: Record<string, TierDef>;
	policy_matrix: Record<string, Record<string, Record<string, string>>>;
	tool_overrides: ToolOverride[];
};

export type TierDef = {
	description: string;
	allow: { tool_names?: string[]; tool_patterns?: string[] };
	quotas: {
		max_calls_per_request?: number;
		max_calls_per_tool?: number;
		max_parallel?: number;
		max_response_bytes?: number;
	};
	callers?: {
		allow_callers?: Array<{ type: string }>;
		require_signed_caller?: boolean;
		require_human_approval?: boolean;
	};
	redaction: {
		mode: "off" | "block" | "patterns";
		max_output_bytes_to_model?: number;
		patterns?: Array<{ name: string; regex: string; flags?: string }>;
	};
};

export type ToolOverride = {
	match: { name?: string; pattern?: string };
	force_tier?: string;
	reason?: string;
	quotas?: Partial<TierDef["quotas"]>;
	redaction?: Partial<TierDef["redaction"]>;
};

// Validate that T0_DENY tiers cannot have non-empty allow lists.
// Fails loudly at load time — not silently at runtime.
function assertNoDenyLeak(policy: PolicyDoc): void {
	for (const [tierId, tier] of Object.entries(policy.tiers)) {
		if (!tierId.includes("DENY")) continue;
		const names = tier.allow?.tool_names ?? [];
		const patterns = tier.allow?.tool_patterns ?? [];
		if (names.length > 0 || patterns.length > 0) {
			throw new Error(
				`Policy integrity error: tier "${tierId}" is a DENY tier but has non-empty allow lists. ` +
					`This would silently permit tools. Remove tool_names/tool_patterns from this tier.`,
			);
		}
	}

	// Also check force_tier overrides — if override forces T0_DENY but the tier has allows, same problem
	for (const o of policy.tool_overrides ?? []) {
		if (o.force_tier && o.force_tier.includes("DENY")) {
			const tier = policy.tiers[o.force_tier];
			if (!tier)
				throw new Error(
					`tool_override references unknown force_tier: ${o.force_tier}`,
				);
		}
	}
}

function assertValidRegexes(policy: PolicyDoc): void {
	for (const [tierId, tier] of Object.entries(policy.tiers)) {
		for (const pattern of tier.redaction.patterns ?? []) {
			try {
				buildPolicyRegExp(pattern.regex, pattern.flags, "g");
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				throw new Error(
					`Policy regex error in tier "${tierId}" pattern "${pattern.name}": ${msg}`,
				);
			}
		}
	}
}

export function loadPolicy(filePath: string): PolicyDoc {
	const raw = fs.readFileSync(filePath, "utf8");
	const policy = yaml.parse(raw) as PolicyDoc;
	assertNoDenyLeak(policy);
	assertValidRegexes(policy);
	return policy;
}

export function listPolicySets(policy: PolicyDoc) {
	return (policy.policy_sets ?? []).map((p) => ({ id: p.id, label: p.label }));
}

export function resolvePolicySetId(
	policy: PolicyDoc,
	identity: string,
): string {
	const id = policy.identities?.[identity]?.default_policy_set;
	if (!id) throw new Error(`No default_policy_set for identity="${identity}"`);
	return id;
}

export function resolveTierId(
	policy: PolicyDoc,
	policySetId: string,
	identity: string,
	trigger: string,
): string {
	const tier = policy.policy_matrix?.[policySetId]?.[identity]?.[trigger];
	if (!tier) {
		throw new Error(
			`No tier mapping for policy_set="${policySetId}" identity="${identity}" trigger="${trigger}"`,
		);
	}
	return tier;
}
