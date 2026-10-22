# ADR 0003: BGP and Routing Safety Guardrails

## Status
Accepted

## Context
Automated routing optimization platforms (comparable to Noction IRP) interact directly with autonomous systems and Internet exchange points. Erroneous route announcements or misconfigured BGP updates can lead to global route leaks, blackholing of critical customer traffic, or carrier-level SLA breaches.

Operational safety must be deeply baked into the platform architecture and cannot be an afterthought or an optional toggle.

## Decision
We enforce the following non-negotiable guardrails across all layers of the platform:
1. **Disabled by Default**:
   - `ROUTING_EXECUTION_ENABLED` defaults to `false` in `.env.example`, Docker Compose configurations, and runtime settings.
   - Any API request attempting to execute a route announcement against a production peer while this flag is `false` returns HTTP 403 Forbidden with structured error code `ERR_ROUTING_EXECUTION_DISABLED`.
2. **Deny-by-Default Allowlisting**:
   - Every route announcement or withdrawal candidate must strictly match a configured `PrefixAllowlist` entry.
   - Default routes (`0.0.0.0/0`, `::/0`), bogons (e.g., RFC 1918, RFC 6598, multicast `224.0.0.0/4`), and prefixes outside approved length limits (IPv4: `/16` to `/24`, IPv6: `/32` to `/48`) are permanently rejected during Pydantic schema validation.
3. **Multi-Stage Change Workflow with Dual Approval**:
   - Route changes follow a 6-stage lifecycle: `Draft` $\to$ `Simulated` $\to$ `Pending Approval` $\to$ `Approved` $\to$ `Executed` $\to$ `Post-check Validated`.
   - The user who creates or simulates a recommendation cannot approve it if the change risk level is rated high.
4. **Idempotency and Anti-Oscillation**:
   - Each recommendation includes an anti-oscillation timer (configurable hold-down window, minimum 15 minutes).
   - Re-applying the same route policy does not duplicate BGP sessions or trigger redundant route updates.
5. **Emergency Circuit Breaker**:
   - If the rate of route changes exceeds the safe delta threshold (e.g., > 10 changes within 5 minutes) or if telemetry reports severe packet loss degradation after execution, the circuit breaker trips, all active changes are automatically rolled back, and routing control is frozen until manual operator intervention.

## Consequences
- **Positive**:
  - Eliminates the risk of catastrophic route hijacking or accidental configuration broadcast during testing and onboarding.
  - Full auditability for compliance and post-incident root cause analysis.
- **Negative / Trade-offs**:
  - Slower end-to-end execution path requiring explicit operator review and approvals.
