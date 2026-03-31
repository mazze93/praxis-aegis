import type { TierDef } from "../policy/loader.js";

export function toolAllowedOrThrow(toolName: string, tier: TierDef): void {
	const allow = tier.allow ?? {};
	const toolNames = allow.tool_names ?? [];
	const toolPatterns = allow.tool_patterns ?? [];

	const byName = toolNames.includes(toolName);
	const byPattern = toolPatterns.some((pat) => new RegExp(pat).test(toolName));

	if (!byName && !byPattern) {
		throw new Error(`Tool "${toolName}" is not permitted by the active tier`);
	}
}
