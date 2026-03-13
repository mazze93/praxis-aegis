# praxis-aegis — Agentic Context

## What this is and why it exists

praxis-aegis is the **Agentic Trust layer** of the Praxis personal OS. It sits between AI model
runtimes and the tools those models are allowed to invoke on the user's behalf.

The threat it addresses: when you give an AI agent access to real tools (filesystem, APIs,
messaging), the agent acquires your context and your reach simultaneously. Without a chokepoint,
a compromised model, a malicious prompt injection, or simple scope creep can act with your
full authority. praxis-aegis is that chokepoint.

It enforces:
- **Who can authenticate** — hardware security key (SSH signature), not an API key
- **What context is declared** — identity + trigger + policy set = explicit operational scope
- **What tools are permitted** — tier-based allowlists with per-tool overrides
- **What the model can see** — output redaction strips PII, credentials, and oversized responses
- **How many calls are allowed** — quota enforcement per request sequence

## Where it fits in Praxis

```
DAEDALUS     — Who you are, operationally (VPN, terminal, FS, SSH keys)
ContextSynapse — What you know and remember (Bayesian priors, adaptive memory)
praxis-aegis — What an AI is permitted to do, as you           ← here
```

These three layers compose. praxis-aegis is the newest — it was not in the original Praxis
architecture because the AI agent problem hadn't materialized yet. It should be understood as
the third dimension of identity sovereignty: not just who you are and what you know, but what
acts are permitted in your name.

Integration opportunities (not yet built):
- `daedalus switch <context>` → should also initiate/tear down a praxis-aegis session
- ContextSynapse intent weights → could inform trigger selection (research/ops/write/admin)
  without requiring explicit per-call declaration

## Development Workflow

**Intent → Plan → Explain → Verify → Execute → Explain → Verify → Plan**

This is not ceremony. This project enforces security boundaries. A change that seems small
can open an enforcement gap. Before touching code:

1. **State your intent** — what problem are you solving and why?
2. **Plan the change** — which files, what logic, what invariants does it touch?
3. **Explain the tradeoffs** — what does this make easier? What does it make harder?
4. **Verify the plan** — does it preserve the invariants below?
5. **Execute** — make the change, keep it minimal
6. **Explain what changed** — write it down, not just in code
7. **Verify the outcome** — `tsc --noEmit`, test the enforcement path manually

If you are uncertain about a design decision, stop and ask. Do not invent security policy.

## Enforcement Invariants — Never Break These

1. **Authentication before enforcement** — `requireSession` must run before `invoke-tool` processes anything
2. **Identity lock** — the request's declared identity MUST match the session identity; the model cannot elevate by claiming a different identity
3. **Synchronous quota** — quota check and increment are synchronous with no `await` between them; do not introduce async between these operations or you create a race condition
4. **Redaction is on egress** — the gateway redacts output *to the model*, not input to backends; backends receive raw results and that is correct
5. **DENY tiers have empty allow lists** — enforced by `assertNoDenyLeak()` at policy load; do not weaken this check
6. **policy_set_id is not model-controllable** — only a human/system operator selects the policy set; the model passes it through but the gateway validates it

## Known Design Tensions

### Quota semantics
`quota.release(requestId)` runs in the `finally` block of every `/invoke-tool` POST. Since each
HTTP POST is one tool call, the quota resets after every single invocation. This means
`max_calls_per_request` currently measures per-HTTP-request (always 1), not per-agentic-sequence.

The design intent was: same `requestId` travels with multiple tool calls in an agentic sequence,
accumulating quota. This requires either:
- Remove `release()` from the finally block and add explicit lifecycle management (a `/release`
  endpoint or session-level cleanup)
- Or rename the field and accept it's a per-call limit (effectively useless as written)

**Status**: unresolved. Do not silently "fix" this without understanding the intended lifecycle.

### Caller token chicken-and-egg
`require_signed_caller: true` means the model runtime must produce an HMAC-signed token with
the `request_id`. But the `request_id` is provided BY the caller in the request body — so the
orchestrator upstream of the gateway must pre-sign calls before sending them. This only works
with a trusted orchestrator. Solo model invocations cannot satisfy this requirement without
a pre-signing layer. The feature is correct by design but assumes a deployment topology that
isn't yet documented.

### Backend authentication
HTTP backends receive tool calls with no proof they came from praxis-aegis. A shared HMAC
header on the aegis→backend leg would close this. Not yet implemented.

## Critical Files

| File | Purpose |
|------|---------|
| `tool_risk_tier.yaml` | The policy. All tier definitions, identity mappings, tool overrides, redaction rules live here. This is the source of truth — not the code. |
| `src/routes/invoke.ts` | The enforcement pipeline. The ordered sequence of checks (caller → allow → quota → backend → redact) is the core contract. |
| `src/policy/loader.ts` | Policy parsing and integrity checks. `assertNoDenyLeak` runs at load time. |
| `src/policy/resolve.ts` | Tool override resolution and tier merging. |
| `src/enforce/quota.ts` | Synchronous quota tracking. Read carefully before modifying. |
| `src/enforce/redact.ts` | Output redaction. UTF-8-safe truncation matters. |
| `src/auth/ssh.ts` | SSH signature verification via `ssh-keygen -Y verify`. Uses `spawnSync` for stdin. |
| `src/auth/session.ts` | Challenge-response session management. In-process store — Redis for multi-instance. |
| `src/backends/registry.ts` | Tool router. Register backends here as services come online. |
| `src/server.ts` | App factory. Tool router is instantiated here; backends are registered here. |

## Stack

- TypeScript (ESM, strict), Node 20+
- Express 4 — HTTP server
- Zod — schema validation at every boundary
- jsonwebtoken — session JWT
- yaml — policy parsing
- No ORM, no database, no cloud dependencies

## What Not To Do

- Do not add cloud dependencies or require external state for the happy path
- Do not weaken the `requireSession` guard on any enforcement route
- Do not allow the model to influence `policy_set_id` selection without validation
- Do not move the quota check/increment across an `await` boundary
- Do not remove `assertNoDenyLeak()` from the policy loader
- Do not add redaction on the *input* path — it belongs on egress only
- Do not make the enforcement pipeline configurable at request time — policy is in YAML, loaded at startup
- Do not skip the Identity mismatch check in `invoke.ts` for "convenience"
