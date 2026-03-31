import type { PolicyDoc, TierDef, ToolOverride } from "./loader.js";

export function findToolOverride(
	policy: PolicyDoc,
	toolName: string,
): ToolOverride | null {
	for (const o of policy.tool_overrides ?? []) {
		const m = o.match ?? {};
		if (m.name && m.name === toolName) return o;
		if (m.pattern && new RegExp(m.pattern).test(toolName)) return o;
	}
	return null;
}

function mergeTierWithOverride(tier: TierDef, override: ToolOverride): TierDef {
	return {
		...tier,
		quotas: { ...tier.quotas, ...(override.quotas ?? {}) },
		redaction: { ...tier.redaction, ...(override.redaction ?? {}) },
	};
}

export type ResolvedTier = {
	tierId: string;
	tier: TierDef;
	override: ToolOverride | null;
};

export function resolveEffectiveTier(
	policy: PolicyDoc,
	baseTierId: string,
	toolName: string,
): ResolvedTier {
	const override = findToolOverride(policy, toolName);

	if (override?.force_tier) {
		const forcedId = override.force_tier;
		const forced = policy.tiers?.[forcedId];
		if (!forced)
			throw new Error(`Override references unknown tier: ${forcedId}`);
		return { tierId: forcedId, tier: forced, override };
	}

	const tier = policy.tiers?.[baseTierId];
	if (!tier) throw new Error(`Unknown tier: ${baseTierId}`);

	return {
		tierId: baseTierId,
		tier: override ? mergeTierWithOverride(tier, override) : tier,
		override,
	};
}
