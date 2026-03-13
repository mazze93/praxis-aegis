import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { config } from "../config.js";

export type SessionPayload = {
  identity: string;
  iat: number;
  exp: number;
};

type ChallengeEntry = {
  identity: string;
  nonce: string;
  expiresAt: number; // unix ms
};

// In-process challenge store. Keys are challenge_ids (UUID v4).
// In multi-instance deployments, replace with Redis.
const challenges = new Map<string, ChallengeEntry>();

// Prune expired challenges lazily on each store access
function pruneExpired(): void {
  const now = Date.now();
  for (const [id, entry] of challenges) {
    if (entry.expiresAt < now) challenges.delete(id);
  }
}

export function createChallenge(identity: string): { challenge_id: string; nonce: string } {
  pruneExpired();

  const challenge_id = crypto.randomUUID();
  const nonce = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + config.CHALLENGE_TTL_SECONDS * 1000;

  challenges.set(challenge_id, { identity, nonce, expiresAt });
  return { challenge_id, nonce };
}

export function consumeChallenge(
  challenge_id: string,
  identity: string
): { nonce: string } | null {
  pruneExpired();

  const entry = challenges.get(challenge_id);
  if (!entry) return null;
  if (entry.identity !== identity) return null;
  if (entry.expiresAt < Date.now()) {
    challenges.delete(challenge_id);
    return null;
  }

  // Consume: challenges are single-use
  challenges.delete(challenge_id);
  return { nonce: entry.nonce };
}

export function issueSessionToken(identity: string): string {
  const payload: Omit<SessionPayload, "iat" | "exp"> = { identity };
  return jwt.sign(payload, config.SESSION_JWT_SECRET, {
    expiresIn: `${config.SESSION_TTL_HOURS}h`,
    algorithm: "HS256",
  });
}

export function verifySessionToken(token: string): SessionPayload {
  const decoded = jwt.verify(token, config.SESSION_JWT_SECRET, {
    algorithms: ["HS256"],
  });
  return decoded as SessionPayload;
}
