import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  POLICY_PATH: z.string().default(path.join(projectRoot, "tool_risk_tier.yaml")),
  ALLOWED_SIGNERS_DIR: z.string().default(path.join(projectRoot, "allowed_signers")),
  ADMIN_IDENTITIES: z
    .string()
    .default("")
    .transform((value) =>
      value
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    ),
  BACKEND_ASSERTION_SECRET: z.string().min(32),
  // HMAC secret for signing/verifying caller tokens (min 32 hex chars = 16 bytes)
  CALLER_HMAC_SECRET: z.string().min(32),
  // JWT secret for session tokens (min 32 hex chars)
  SESSION_JWT_SECRET: z.string().min(32),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(72).default(8),
  CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(300),
  RATE_LIMIT_CHALLENGE_PER_MIN: z.coerce.number().int().min(1).max(60).default(10),
  // Optional backend service URLs — register routes in server.ts when these are set
  SEARCH_SERVICE_URL: z.string().url().optional(),
  DATA_SERVICE_URL: z.string().url().optional(),
});

function loadConfig() {
  const result = schema.safeParse(process.env);
  if (!result.success) {
    const issues = result.error.issues
      .map((i: z.ZodIssue) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Configuration error:\n${issues}`);
  }
  return result.data;
}

export const config = loadConfig();
export type Config = typeof config;
