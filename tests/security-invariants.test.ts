import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

process.env.CALLER_HMAC_SECRET ??= "0123456789abcdef0123456789abcdef";
process.env.SESSION_JWT_SECRET ??= "fedcba9876543210fedcba9876543210";
process.env.ADMIN_IDENTITIES ??= "daedalus";
process.env.BACKEND_ASSERTION_SECRET ??= "00112233445566778899aabbccddeeff";

const { loadPolicy } = await import("../src/policy/loader.ts");
const { createInvokeRouter } = await import("../src/routes/invoke.ts");
const { createPolicyRouter } = await import("../src/routes/policy.ts");
const { QuotaTracker } = await import("../src/enforce/quota.ts");
const { buildCallerToken } = await import("../src/enforce/caller.ts");
const { issueSessionToken } = await import("../src/auth/session.ts");
const { invokeHttpBackend, ToolBackendError } = await import(
	"../src/backends/http.ts"
);
const { verifyBackendAssertion } = await import("../src/backends/assertion.ts");
const { redactOutput } = await import("../src/enforce/redact.ts");

type MockRequest = {
	body?: unknown;
	headers: Record<string, string>;
	session?: {
		identity: string;
	};
};

type MockResponse = {
	statusCode: number;
	body?: unknown;
	status: (code: number) => MockResponse;
	json: (payload: unknown) => MockResponse;
};

type ExpressHandler = (
	req: MockRequest,
	res: MockResponse,
	next: (err?: unknown) => void,
) => unknown;

const policyPath = fileURLToPath(
	new URL("../tool_risk_tier.yaml", import.meta.url),
);
const policy = loadPolicy(policyPath);

function getPostHandlers(
	router: {
		stack: Array<{
			route?: {
				path: string;
				methods: Record<string, boolean>;
				stack: Array<{ handle: ExpressHandler }>;
			};
		}>;
	},
	path: string,
): ExpressHandler[] {
	const layer = router.stack.find(
		(entry) => entry.route?.path === path && entry.route.methods.post,
	);
	if (!layer?.route) throw new Error(`POST route not found: ${path}`);
	return layer.route.stack.map((entry) => entry.handle);
}

async function runHandlers(
	handlers: ExpressHandler[],
	req: MockRequest,
): Promise<MockResponse> {
	const res: MockResponse = {
		statusCode: 200,
		status(code: number) {
			this.statusCode = code;
			return this;
		},
		json(payload: unknown) {
			this.body = payload;
			return this;
		},
	};

	const invokeAt = async (index: number): Promise<void> => {
		const handler = handlers[index];
		if (!handler) return;

		let nextCalled = false;

		await new Promise<void>((resolve, reject) => {
			const next = (err?: unknown) => {
				if (err) {
					reject(err);
					return;
				}
				nextCalled = true;
				resolve();
			};

			try {
				Promise.resolve(handler(req, res, next)).then(() => {
					if (!nextCalled) resolve();
				}, reject);
			} catch (err) {
				reject(err);
			}
		});

		if (nextCalled) await invokeAt(index + 1);
	};

	await invokeAt(0);
	return res;
}

function sessionHeaders(identity: string): Record<string, string> {
	return {
		authorization: `Bearer ${issueSessionToken(identity)}`,
	};
}

test("invoke-tool rejects request-controlled policy_set_id", async () => {
	const router = createInvokeRouter(
		() => policy,
		new QuotaTracker(),
		async () => ({ ok: true }),
	);
	const handlers = getPostHandlers(
		router as unknown as {
			stack: Array<{
				route?: {
					path: string;
					methods: Record<string, boolean>;
					stack: Array<{ handle: ExpressHandler }>;
				};
			}>;
		},
		"/",
	);

	const res = await runHandlers(handlers, {
		headers: sessionHeaders("daedalus"),
		body: {
			request_id: "req-policy-set-reject",
			tool_name: "search_documents",
			input: { query: "policy" },
			meta: {
				identity: "daedalus",
				trigger: "research",
				policy_set_id: "daedalus_dev",
			},
		},
	});

	assert.equal(res.statusCode, 400);
	assert.match(JSON.stringify(res.body), /policy_set_id/);
});

test("invoke-tool sanitizes backend failures before returning them", async (t) => {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = (async () =>
		({
			ok: false,
			status: 500,
			text: async () => "SECRET_TOKEN=supersecret-value",
		}) as Response) as typeof fetch;

	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	const router = createInvokeRouter(
		() => policy,
		new QuotaTracker(),
		(toolName: string, input: unknown) =>
			invokeHttpBackend(
				{
					type: "http",
					baseUrl: "http://backend.internal",
					assertionSecret: process.env.BACKEND_ASSERTION_SECRET as string,
					audience: "backend.internal",
				},
				toolName,
				input,
				{
					requestId: "req-backend-failure",
					identity: "daedalus",
					policySetId: "daedalus_prod",
					tierId: "T1_READONLY",
					callerType: "model",
				},
			),
	);
	const handlers = getPostHandlers(
		router as unknown as {
			stack: Array<{
				route?: {
					path: string;
					methods: Record<string, boolean>;
					stack: Array<{ handle: ExpressHandler }>;
				};
			}>;
		},
		"/",
	);

	const now = Math.floor(Date.now() / 1000);
	const signedToken = buildCallerToken(
		{
			request_id: "req-backend-failure",
			identity: "daedalus",
			caller_type: "model",
			tool_name: "search_documents",
			iat: now,
			exp: now + 60,
		},
		process.env.CALLER_HMAC_SECRET as string,
	);

	const res = await runHandlers(handlers, {
		headers: sessionHeaders("daedalus"),
		body: {
			request_id: "req-backend-failure",
			tool_name: "search_documents",
			input: { query: "top secret" },
			caller: {
				type: "model",
				signed_token: signedToken,
			},
			meta: {
				identity: "daedalus",
				trigger: "research",
			},
		},
	});

	assert.equal(res.statusCode, 502);
	assert.equal(
		(res.body as { error: string }).error,
		"Tool backend error for search_documents",
	);
	assert.doesNotMatch(JSON.stringify(res.body), /supersecret-value/);
	assert.doesNotMatch(JSON.stringify(res.body), /SECRET_TOKEN/);

	await assert.rejects(
		() =>
			invokeHttpBackend(
				{
					type: "http",
					baseUrl: "http://backend.internal",
					assertionSecret: process.env.BACKEND_ASSERTION_SECRET as string,
					audience: "backend.internal",
				},
				"search_documents",
				{ query: "top secret" },
				{
					requestId: "req-backend-failure",
					identity: "daedalus",
					policySetId: "daedalus_prod",
					tierId: "T1_READONLY",
					callerType: "model",
				},
			),
		(err: unknown) => {
			assert.ok(err instanceof ToolBackendError);
			assert.equal(err.safeMessage, "Tool backend error for search_documents");
			assert.match(err.internalDetail ?? "", /SECRET_TOKEN=supersecret-value/);
			return true;
		},
	);
});

test("policy reload requires an administrative session", async () => {
	let reloadCount = 0;

	const router = createPolicyRouter(
		() => policy,
		() => {
			reloadCount += 1;
		},
	);
	const handlers = getPostHandlers(
		router as unknown as {
			stack: Array<{
				route?: {
					path: string;
					methods: Record<string, boolean>;
					stack: Array<{ handle: ExpressHandler }>;
				};
			}>;
		},
		"/reload",
	);

	const nonAdminRes = await runHandlers(handlers, {
		headers: sessionHeaders("secure_pride"),
	});

	assert.equal(nonAdminRes.statusCode, 403);
	assert.equal(reloadCount, 0);

	const adminRes = await runHandlers(handlers, {
		headers: sessionHeaders("daedalus"),
	});

	assert.equal(adminRes.statusCode, 200);
	assert.equal(reloadCount, 1);
});

test("caller tokens are bound to identity, caller type, and tool", async () => {
	const router = createInvokeRouter(
		() => policy,
		new QuotaTracker(),
		async () => ({ ok: true }),
	);
	const handlers = getPostHandlers(
		router as unknown as {
			stack: Array<{
				route?: {
					path: string;
					methods: Record<string, boolean>;
					stack: Array<{ handle: ExpressHandler }>;
				};
			}>;
		},
		"/",
	);

	const now = Math.floor(Date.now() / 1000);
	const signedToken = buildCallerToken(
		{
			request_id: "req-bound-caller",
			identity: "daedalus",
			caller_type: "model",
			tool_name: "search_documents",
			iat: now,
			exp: now + 60,
		},
		process.env.CALLER_HMAC_SECRET as string,
	);

	const wrongToolRes = await runHandlers(handlers, {
		headers: sessionHeaders("daedalus"),
		body: {
			request_id: "req-bound-caller",
			tool_name: "list_documents",
			input: { query: "policy" },
			caller: {
				type: "model",
				signed_token: signedToken,
			},
			meta: {
				identity: "daedalus",
				trigger: "research",
			},
		},
	});

	assert.equal(wrongToolRes.statusCode, 403);
	assert.match(JSON.stringify(wrongToolRes.body), /tool_name mismatch/);
});

test("redaction patterns from policy YAML compile and redact using explicit flags", () => {
	const t1 = policy.tiers.T1_READONLY;
	const apiKeyOutput = redactOutput(
		"secret = supersecretvalue12345 contact me@example.com",
		t1.redaction,
	);
	const bearerOutput = redactOutput(
		"authorization: bearer abcdEFGHijkl1234._-+/=",
		t1.redaction,
	);

	assert.match(apiKeyOutput, /\[REDACTED:api_keys_generic\]/);
	assert.match(apiKeyOutput, /\[REDACTED:email\]/);
	assert.match(bearerOutput, /\[REDACTED:bearer\]/);
});

test("invokeHttpBackend attaches a verifiable gateway assertion", async (t) => {
	const originalFetch = globalThis.fetch;
	let capturedAssertion: string | null = null;
	let capturedRequestId: string | null = null;

	globalThis.fetch = (async (_url, init) => {
		const headers = new Headers(init?.headers);
		capturedAssertion = headers.get("x-praxis-aegis-assertion");
		capturedRequestId = headers.get("x-praxis-aegis-request-id");

		return {
			ok: true,
			json: async () => ({ ok: true }),
		} as Response;
	}) as typeof fetch;

	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	await invokeHttpBackend(
		{
			type: "http",
			baseUrl: "http://backend.internal",
			assertionSecret: process.env.BACKEND_ASSERTION_SECRET as string,
			audience: "search-service",
		},
		"search_documents",
		{ query: "policy" },
		{
			requestId: "req-assertion",
			identity: "daedalus",
			policySetId: "daedalus_prod",
			tierId: "T1_READONLY",
			callerType: "model",
		},
	);

	assert.equal(capturedRequestId, "req-assertion");
	assert.ok(capturedAssertion);

	const verification = verifyBackendAssertion(
		capturedAssertion ?? undefined,
		process.env.BACKEND_ASSERTION_SECRET as string,
		{
			audience: "search-service",
			toolName: "search_documents",
		},
	);

	assert.equal(verification.ok, true);
	assert.equal(verification.payload?.identity, "daedalus");
	assert.equal(verification.payload?.tier_id, "T1_READONLY");
});
