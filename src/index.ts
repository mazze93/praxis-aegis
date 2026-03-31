import { config } from "./config.js";
import { createApp } from "./server.js";

const app = createApp();

app.listen(config.PORT, () => {
	console.log(`[praxis-aegis] Listening on :${config.PORT}`);
	console.log(`[praxis-aegis] Policy: ${config.POLICY_PATH}`);
	console.log(`[praxis-aegis] Allowed signers: ${config.ALLOWED_SIGNERS_DIR}`);
	console.log(
		"[praxis-aegis] Session auth required — POST /session/challenge to begin",
	);
});
