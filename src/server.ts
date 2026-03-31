import express from "express";
import { ToolRouter } from "./backends/registry.js";
import { config } from "./config.js";
import { QuotaTracker } from "./enforce/quota.js";
import { loadPolicy } from "./policy/loader.js";
import { createInvokeRouter } from "./routes/invoke.js";
import { createPolicyRouter } from "./routes/policy.js";
import { sessionRouter } from "./routes/session.js";

export function createApp() {
	let policy = loadPolicy(config.POLICY_PATH);
	const quota = new QuotaTracker();

	const toolRouter = new ToolRouter();
	// Register backends here as services come online. Examples:
	//   toolRouter.register({
	//     match: /^search_/,
	//     backend: {
	//       type: "http",
	//       baseUrl: config.SEARCH_SERVICE_URL!,
	//       assertionSecret: config.BACKEND_ASSERTION_SECRET,
	//       audience: "search-service",
	//     },
	//   });
	//   toolRouter.register({
	//     match: /^get_/,
	//     backend: {
	//       type: "http",
	//       baseUrl: config.DATA_SERVICE_URL!,
	//       assertionSecret: config.BACKEND_ASSERTION_SECRET,
	//       audience: "data-service",
	//     },
	//   });
	//   toolRouter.register({
	//     match: "ping",
	//     backend: { type: "local", handler: async () => ({ pong: true }) },
	//   });

	const app = express();
	app.use(express.json({ limit: "2mb" }));

	// Disable fingerprinting
	app.disable("x-powered-by");

	// Health check — no auth required
	app.get("/health", (_req, res) => {
		res.json({ ok: true, service: "praxis-aegis" });
	});

	// Session auth flow — hardware key challenge + unlock
	app.use("/session", sessionRouter);

	// Policy management — authenticated
	app.use(
		"/policy",
		createPolicyRouter(
			() => policy,
			() => {
				policy = loadPolicy(config.POLICY_PATH);
			},
		),
	);

	/**
	 * Tool invocation — the main enforcement surface.
	 *
	 * callToolBackend routes to registered backends via ToolRouter.
	 * Register backends above (HTTP services, local handlers) as they come online.
	 *
	 * Important: callToolBackend MUST NOT receive unredacted output from
	 * prior tool calls. The gateway's redact step applies on the way *out*
	 * to the model, not on the way *in* to backends.
	 */
	app.use(
		"/invoke-tool",
		createInvokeRouter(
			() => policy,
			quota,
			toolRouter.dispatch.bind(toolRouter),
		),
	);

	// 404 fallthrough
	app.use((_req, res) => {
		res.status(404).json({ ok: false, error: "Not found" });
	});

	return app;
}
