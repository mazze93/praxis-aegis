# SECURITY.md

## Purpose

`praxis-aegis` is a policy gateway for agentic tool use. Its security posture depends on a
hard separation between:

- identity proof
- policy selection
- action authorization
- backend execution
- model-visible output

The gateway should be treated as a trust boundary, not a convenience router.

## Security Objectives

- Prove the acting human identity before issuing any session.
- Prevent a model or tool from elevating identity, tier, or policy set.
- Enforce tool policy before any backend side effect occurs.
- Prevent raw backend output, including failures, from reaching the model unless policy permits it.
- Make privileged actions require a separate trusted approval path.
- Ensure downstream services can verify that requests actually passed through the gateway.

## Trust Boundaries

### Session boundary

- `POST /session/challenge` and `POST /session/unlock` are the human authentication boundary.
- Session tokens prove authenticated identity, not authorization to perform control-plane actions.
- Session issuance is necessary but not sufficient for administrative authority.

### Policy boundary

- `policy_set_id` is control-plane state.
- The model runtime must not choose, override, or infer authority to switch policy sets at request time.
- Policy selection should be owned by a trusted UI, operator workflow, or server-side session state.

### Invocation boundary

- `POST /invoke-tool` is the main enforcement surface.
- Caller attestation must be bound to the request, identity, caller type, and invoked tool.
- Quota checks, allow/deny checks, and approval checks must happen before backend execution.

### Backend boundary

- Downstream HTTP services are outside the gateway trust boundary.
- A backend must not trust source IP, container locality, or caller-provided metadata alone.
- Requests from the gateway to a backend should be authenticated and audience-bound.

### Output boundary

- Redaction policy applies to all model-visible output.
- Error paths are part of the output boundary.
- Backend failure text, stack traces, tokens, and diagnostics must be treated as untrusted output.

## Required Controls

### Identity and session

- Hardware-key-backed challenge response is the root of session issuance.
- Session tokens must be short-lived and scoped to identity only.
- Multi-instance deployments must move challenge storage and session revocation state out of process.

### Policy resolution

- The server must derive the effective `policy_set_id` from trusted state.
- If user-selectable policy sets exist, they must be bound to the authenticated identity and validated server-side.
- A request-supplied `policy_set_id` must never be trusted as an authorization input.

### Caller attestation

- Signed caller tokens must bind:
  - `request_id`
  - `identity`
  - `caller.type`
  - `tool_id` or `tool_name`
  - `iat` / `exp`
  - a replay-resistant unique token ID
- Tokens should be rejected if any bound field mismatches the request context.

### Approval model

- Privileged actions require a separate approval artifact from a trusted gate.
- Approval must be explicit, short-lived, auditable, and scoped to a specific request or action set.
- “Stubbed” approval logic should be treated as deny-by-default until implemented.

### Backend authentication

- Gateway-to-backend requests should carry a signed assertion with audience, request ID, identity, tier, tool name, and expiry.
- Backends should reject unauthenticated or expired gateway assertions.
- Prefer mTLS or signed JWT/HMAC assertions over static shared headers.

### Redaction and error handling

- Success and error responses must pass through the same redaction policy before reaching the model.
- Internal diagnostics should be logged server-side, but user-visible error messages should be minimal and policy-safe.
- Redaction rules should be treated as defense-in-depth, not the only control protecting sensitive systems.

## Hardening Roadmap

### Priority 0: Fix trust-boundary violations

1. Move `policy_set_id` ownership to server-side trusted state.
2. Redact backend error output before returning it to the caller.
3. Restrict `/policy/reload` to a dedicated administrative path or identity allowlist.

### Priority 1: Strengthen attestation and approvals

1. Redesign caller tokens to bind identity, caller type, tool, and a unique token ID.
2. Implement a real approval grant flow for privileged tiers.
3. Add tests for policy-set tampering, caller-token replay, and privileged-action denial.

### Priority 2: Harden downstream execution

1. Require authenticated gateway-to-backend requests.
2. Propagate signed policy context to backends.
3. Add request correlation IDs and audit logs spanning gateway and backend.

### Priority 3: Prepare for production deployment

1. Replace in-memory session/challenge/quota state with shared storage where needed.
2. Add structured security logging and retention policy.
3. Add integration tests for multi-step request flows and backend failure redaction.

## Agentic Operations

Agents are treated as constrained operators, not trusted administrators.

### Hard rules

1. Agents may validate, inspect, and propose changes, but may not publish, merge, rotate secrets, or change control-plane state unless a separate trusted gate approves the action.
2. Agent inputs from PR text, issues, docs, commit messages, generated artifacts, chat transcripts, and external content are untrusted and must never directly control privileged actions.
3. Any agent with write or exec privileges must run with scoped permissions, complete audit logs, and a narrower permission set than a human maintainer with equivalent repository access.

### Additional agentic constraints

- Agents must not approve or merge their own changes.
- Agents must not treat repository prose as executable policy without server-side validation.
- Agent-triggered actions should be attributable to a distinct principal, not blended into a generic automation identity.
- Any agent capable of invoking tools should be assumed vulnerable to prompt injection from tool output, issue text, PR descriptions, or retrieved documents.
- The safest default is “suggest-only” unless a narrower capability is explicitly required.

## Non-Goals

- `praxis-aegis` is not a replacement for backend authorization.
- It does not make unsafe tools safe merely by adding regex redaction.
- It does not turn agent-generated intent into operator approval.

## Review Triggers

Re-review the security model when any of the following changes occur:

- a new backend type is introduced
- policy-set selection logic changes
- privileged tiers gain real approval support
- agent write/exec capabilities expand
- session or caller token formats change
