import type { TierDef } from "../policy/loader.js";
import { buildPolicyRegExp } from "../policy/regex.js";

/**
 * Walk back from maxBytes until we land on a UTF-8 leading byte.
 * UTF-8 continuation bytes are 0x80–0xBF (top two bits = 10).
 * This avoids producing invalid UTF-8 at the truncation boundary.
 */
function utf8SafeTruncate(buf: Buffer, maxBytes: number): string {
	if (buf.byteLength <= maxBytes) return buf.toString("utf8");

	let i = maxBytes;
	while (i > 0 && (buf[i]! & 0xc0) === 0x80) i--;

	return buf.subarray(0, i).toString("utf8") + "\n[TRUNCATED BY POLICY]";
}

export function redactOutput(
	raw: string,
	redaction: TierDef["redaction"],
): string {
	if (!redaction || redaction.mode === "off") return raw;
	if (redaction.mode === "block") return "[BLOCKED BY POLICY]";

	let out = raw;

	for (const p of redaction.patterns ?? []) {
		const re = buildPolicyRegExp(p.regex, p.flags, "g");
		out = out.replace(re, `[REDACTED:${p.name}]`);
	}

	const max = redaction.max_output_bytes_to_model ?? 100_000;
	const buf = Buffer.from(out, "utf8");
	return utf8SafeTruncate(buf, max);
}
