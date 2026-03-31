import type { NextFunction, Request, Response } from "express";

type Bucket = {
	tokens: number;
	lastRefill: number; // unix ms
};

/**
 * Simple in-process token-bucket rate limiter keyed by IP address.
 * Suitable for single-instance deployments (use Redis for multi-instance).
 */
export function createRateLimiter(maxPerMinute: number) {
	const buckets = new Map<string, Bucket>();
	const refillIntervalMs = 60_000;

	function getIp(req: Request): string {
		return (
			(req.headers["x-forwarded-for"] as string | undefined)
				?.split(",")[0]
				?.trim() ??
			req.socket.remoteAddress ??
			"unknown"
		);
	}

	return function rateLimit(
		req: Request,
		res: Response,
		next: NextFunction,
	): void {
		const ip = getIp(req);
		const now = Date.now();

		let bucket = buckets.get(ip);
		if (!bucket) {
			bucket = { tokens: maxPerMinute, lastRefill: now };
			buckets.set(ip, bucket);
		}

		// Refill proportionally based on elapsed time
		const elapsed = now - bucket.lastRefill;
		const refilled = (elapsed / refillIntervalMs) * maxPerMinute;
		bucket.tokens = Math.min(maxPerMinute, bucket.tokens + refilled);
		bucket.lastRefill = now;

		if (bucket.tokens < 1) {
			res
				.status(429)
				.json({ ok: false, error: "Rate limit exceeded — slow down" });
			return;
		}

		bucket.tokens -= 1;
		next();
	};
}
