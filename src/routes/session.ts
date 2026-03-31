import fs from "node:fs";
import path from "node:path";
import { type Request, type Response, Router } from "express";
import { z } from "zod";
import {
	consumeChallenge,
	createChallenge,
	issueSessionToken,
} from "../auth/session.js";
import { verifySshSignature } from "../auth/ssh.js";
import { config } from "../config.js";
import { createRateLimiter } from "../middleware/rateLimit.js";

export const sessionRouter = Router();

const rateLimiter = createRateLimiter(config.RATE_LIMIT_CHALLENGE_PER_MIN);

const challengeSchema = z.object({
	identity: z.string().min(1).max(64),
});

const unlockSchema = z.object({
	challenge_id: z.string().uuid(),
	identity: z.string().min(1).max(64),
	// Base64-encoded SSH signature (output of `ssh-keygen -Y sign`)
	signature_b64: z.string().min(1),
});

/**
 * POST /session/challenge
 * Returns a nonce the client must sign with their hardware security key.
 * Rate-limited per IP.
 */
sessionRouter.post("/challenge", rateLimiter, (req: Request, res: Response) => {
	const parsed = challengeSchema.safeParse(req.body);
	if (!parsed.success) {
		res.status(400).json({ ok: false, error: parsed.error.flatten() });
		return;
	}

	const { identity } = parsed.data;
	const allowedSignersPath = path.join(config.ALLOWED_SIGNERS_DIR, identity);

	if (!fs.existsSync(allowedSignersPath)) {
		res
			.status(400)
			.json({ ok: false, error: `Unknown identity: "${identity}"` });
		return;
	}

	const { challenge_id, nonce } = createChallenge(identity);

	res.json({
		ok: true,
		challenge_id,
		nonce,
		expires_in_seconds: config.CHALLENGE_TTL_SECONDS,
		instructions: [
			"Sign the following message with your hardware security key:",
			`  printf 'praxis-aegis:${nonce}' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n praxis-aegis`,
			"Then base64-encode the .sig output and submit via POST /session/unlock",
		],
	});
});

/**
 * POST /session/unlock
 * Verifies the SSH signature against the identity's allowed_signers file.
 * On success, issues a session JWT valid for SESSION_TTL_HOURS.
 */
sessionRouter.post(
	"/unlock",
	rateLimiter,
	async (req: Request, res: Response) => {
		const parsed = unlockSchema.safeParse(req.body);
		if (!parsed.success) {
			res.status(400).json({ ok: false, error: parsed.error.flatten() });
			return;
		}

		const { challenge_id, identity, signature_b64 } = parsed.data;

		const consumed = consumeChallenge(challenge_id, identity);
		if (!consumed) {
			res.status(401).json({
				ok: false,
				error: "Challenge not found, expired, or identity mismatch",
			});
			return;
		}

		const allowedSignersPath = path.join(config.ALLOWED_SIGNERS_DIR, identity);
		const result = await verifySshSignature(
			allowedSignersPath,
			identity,
			consumed.nonce,
			signature_b64,
		);

		if (!result.ok) {
			res.status(401).json({
				ok: false,
				error: `Signature verification failed: ${result.reason}`,
			});
			return;
		}

		const session_token = issueSessionToken(identity);

		res.json({
			ok: true,
			session_token,
			identity,
			expires_in_hours: config.SESSION_TTL_HOURS,
		});
	},
);
