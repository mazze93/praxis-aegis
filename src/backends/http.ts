import { buildBackendAssertion } from "./assertion.js";

export interface HttpBackend {
	type: "http";
	baseUrl: string;
	assertionSecret: string;
	audience?: string;
	assertionIssuer?: string;
	assertionTtlSeconds?: number;
	headers?: Record<string, string>;
	timeoutMs?: number;
}

export class ToolBackendError extends Error {
	readonly statusCode: number;
	readonly safeMessage: string;
	readonly internalDetail?: string;

	constructor(
		safeMessage: string,
		options?: {
			statusCode?: number;
			internalDetail?: string;
		},
	) {
		super(safeMessage);
		this.name = "ToolBackendError";
		this.statusCode = options?.statusCode ?? 502;
		this.safeMessage = safeMessage;
		this.internalDetail = options?.internalDetail;
	}
}

export async function invokeHttpBackend(
	backend: HttpBackend,
	toolName: string,
	input: unknown,
	context: {
		requestId: string;
		identity: string;
		policySetId: string;
		tierId: string;
		callerType: "model" | "code_execution";
	},
): Promise<unknown> {
	const timeout = backend.timeoutMs ?? 30_000;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeout);
	const now = Math.floor(Date.now() / 1000);
	const assertion = buildBackendAssertion(
		{
			aud: backend.audience ?? backend.baseUrl,
			iss: backend.assertionIssuer ?? "praxis-aegis",
			request_id: context.requestId,
			identity: context.identity,
			policy_set_id: context.policySetId,
			tier_id: context.tierId,
			caller_type: context.callerType,
			tool_name: toolName,
			iat: now,
			exp: now + (backend.assertionTtlSeconds ?? 60),
		},
		backend.assertionSecret,
	);

	let response: Response;
	try {
		response = await fetch(`${backend.baseUrl}/invoke`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Praxis-Aegis-Assertion": assertion,
				"X-Praxis-Aegis-Request-Id": context.requestId,
				...backend.headers,
			},
			body: JSON.stringify({ tool_name: toolName, input }),
			signal: controller.signal,
		});
	} catch (err) {
		if ((err as Error).name === "AbortError") {
			throw new ToolBackendError(`Tool backend timed out for ${toolName}`, {
				statusCode: 504,
			});
		}
		throw new ToolBackendError(`Tool backend unreachable for ${toolName}`, {
			internalDetail: (err as Error).message,
		});
	} finally {
		clearTimeout(timer);
	}

	if (!response.ok) {
		const body = await response.text().catch(() => "");
		throw new ToolBackendError(`Tool backend error for ${toolName}`, {
			internalDetail: `status=${response.status} body=${body}`,
		});
	}

	return response.json() as Promise<unknown>;
}
