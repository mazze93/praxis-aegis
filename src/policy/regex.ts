export function buildPolicyRegExp(
  pattern: string,
  flags = "",
  extraFlags = ""
): RegExp {
  const normalizedFlags = Array.from(new Set(`${flags}${extraFlags}`.split(""))).join("");
  return new RegExp(pattern, normalizedFlags);
}
