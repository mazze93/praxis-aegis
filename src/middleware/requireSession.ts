import type { NextFunction, Request, Response } from "express";
import { verifySessionToken } from "../auth/session.js";

declare global {
	namespace Express {
		interface Request {
			session?: {
				identity: string;
			};
		}
	}
}

export function requireSession(
	req: Request,
	res: Response,
	next: NextFunction,
): void {
	const authHeader = req.headers["authorization"];
	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		res
			.status(401)
			.json({ ok: false, error: "Missing or malformed Authorization header" });
		return;
	}

	const token = authHeader.slice(7);

	try {
		const payload = verifySessionToken(token);
		req.session = { identity: payload.identity };
		next();
	} catch {
		res
			.status(401)
			.json({ ok: false, error: "Invalid or expired session token" });
	}
}
