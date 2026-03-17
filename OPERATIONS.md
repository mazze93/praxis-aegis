# OPERATIONS.md

## Purpose

This document is the operator runbook for maintaining `praxis-aegis` without weakening its
security model.

Use it when changing policy behavior, deploying new backends, responding to suspicious
activity, or operating agentic workflows around this repository.

## Operating Principles

- Build around explicit trust boundaries, not comments or convention.
- Treat control-plane actions differently from normal tool invocations.
- Prefer deny-by-default when an approval, identity, or attestation signal is missing.
- Keep operators, agents, and downstream services on separate authority planes.

## Current Security Gaps To Close

These are the highest-priority production fixes based on the current implementation.

### 1. Remove request-owned policy-set selection

- Do not accept `policy_set_id` from the normal invocation body as an authorization input.
- Store active policy profile in trusted session state or a server-side operator selection.
- If a human can switch policy profiles, log who switched it, when, and for which identity.

### 2. Sanitize backend failures

- Treat backend error text as untrusted output.
- Log full backend diagnostics internally.
- Return only redacted, minimal, model-safe error content to the caller.

### 3. Restrict control-plane endpoints

- `/policy/reload` should require a stronger gate than any valid session.
- Prefer an explicit admin identity allowlist or a separate operator-only interface.
- Audit every policy reload with identity, time, and policy checksum.

### 4. Bind caller attestations tightly

- Signed caller tokens must be specific to identity, caller type, request ID, and tool.
- Reject tokens missing those bindings.
- Add replay resistance beyond request ID by including a nonce or token ID that is tracked for single use.

### 5. Authenticate downstream backends

- Every backend should verify that the gateway authorized the request.
- Use signed gateway assertions with expiry and audience.
- Reject direct backend calls that bypass the gateway.

## Rollout Order

Apply fixes in this order to reduce risk without breaking the model.

### Phase 1: Close immediate authorization gaps

1. Make policy-set selection server-owned.
2. Redact all backend-originated failure output.
3. Lock down policy reload.

### Phase 2: Improve trust signals

1. Redesign caller tokens.
2. Implement privileged approval grants.
3. Add tests for enforcement invariants.

### Phase 3: Productionize backend trust

1. Add gateway-to-backend authentication.
2. Add structured audit logging and correlation IDs.
3. Add backend-side authorization checks against gateway assertions.

### Phase 4: Scale safely

1. Move session, challenge, and quota state into shared infrastructure when running more than one instance.
2. Add rate limits and alerts for abnormal unlock, reload, and invoke patterns.
3. Review all new tools against policy tiers before registration.

## Agentic Operations

Agentic workflows are useful here, but only if they remain constrained.

### Hard rules

1. Agents can validate and propose, but cannot publish, merge, reload policy, or perform other trusted control-plane actions unless a separate gate approves it.
2. Inputs from PR text, issues, docs, comments, retrieved content, and tool output are untrusted and must never be allowed to directly drive privileged actions.
3. Agents with write or exec rights must run with scoped permissions, complete audit logs, and less authority than a human maintainer.

### Practical operating rules

- Run agents with the minimum filesystem, network, and secret scope needed for the task.
- Separate suggest-only, write-capable, and release-capable automation into different identities.
- Do not let an agent both propose a change and approve its deployment.
- Preserve logs showing which principal initiated a write, exec, or release action.
- Treat tool output and generated patches as untrusted until validated by policy and review.

## Incident Response Guidance

### If policy behavior looks wrong

- Stop using privileged tiers until the policy file and effective tier resolution are verified.
- Confirm the active policy checksum and recent reload history.
- Review whether any request-controlled field influenced authorization.

### If backend output leaks sensitive data

- Assume the error path is compromised until proven otherwise.
- Disable the affected backend route or tool registration if needed.
- Patch redaction and reduce user-visible error detail before restoring service.

### If caller attestation is suspected to be replayable

- Rotate the caller HMAC secret.
- Invalidate active sessions if the trust boundary is unclear.
- Add stricter token binding before re-enabling write-capable flows.

### If an agent behaved outside its intended scope

- Revoke the agent’s credentials or execution environment first.
- Review audit logs for all writes, command executions, and approval attempts.
- Tighten agent permissions before resuming any autonomous workflow.

## Change Management Checklist

Before merging changes that affect the trust layer, confirm:

- policy inputs are server-validated
- privileged actions remain deny-by-default without explicit approval
- error responses are sanitized
- downstream backends authenticate the gateway
- logs preserve who did what, with which authority
- tests cover the changed security invariant

## Documentation Maintenance

Update this file and [SECURITY.md](SECURITY.md) whenever you:

- add a new control-plane endpoint
- change session or caller token structure
- add backend auth mechanisms
- expand agent capabilities
- introduce a new privileged workflow
