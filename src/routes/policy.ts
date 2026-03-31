import { type Request, type Response, Router } from "express";
import { config } from "../config.js";
import { requireSession } from "../middleware/requireSession.js";

function requireAdminIdentity(req: Request, res: Response): boolean {
	const identity = req.session?.identity;
	if (!identity) {
		res.status(401).json({ ok: false, error: "Missing authenticated session" });
		return false;
	}

	if (config.ADMIN_IDENTITIES.length === 0) {
		res.status(403).json({
			ok: false,
			error: "Policy reload is disabled: no admin identities configured",
		});
		return false;
	}

	if (!config.ADMIN_IDENTITIES.includes(identity)) {
		res.status(403).json({
			ok: false,
			error: "Administrative session required for policy reload",
		});
		return false;
	}

	return true;
}

export function createPolicyRouter(
	getPolicy: () => import("../policy/loader.js").PolicyDoc,
	reloadPolicy: () => void,
) {
	const router = Router();

	/**
	 * GET /policy/sets
	 * Returns available carousel policy sets.
	 * Requires a valid session — the model MUST NOT be able to call this directly.
	 */
	router.get("/sets", requireSession, (_req: Request, res: Response) => {
		const policy = getPolicy();
		const sets = (policy.policy_sets ?? []).map(
			(p: { id: string; label: string }) => ({
				id: p.id,
				label: p.label,
			}),
		);
		res.json({ ok: true, policy_sets: sets });
	});

	/**
	 * POST /policy/reload
	 * Hot-reloads the YAML policy file from disk.
	 * Requires an authenticated administrative session.
	 */
	router.post("/reload", requireSession, (req: Request, res: Response) => {
		if (!requireAdminIdentity(req, res)) return;

		try {
			reloadPolicy();
			res.json({ ok: true, message: "Policy reloaded" });
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(500).json({ ok: false, error: msg });
		}
	});

	return router;
}
