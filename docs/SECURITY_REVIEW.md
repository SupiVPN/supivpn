# Security and legacy implementation review

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Fencing findings recorded **2026-09-22**; component isolation and verification
references updated **2026-10-20**.
This is an internal code review with local tests, not independent certification.

## Resolved findings

| Finding | Implemented fix | Regression evidence |
| --- | --- | --- |
| R1: weaker stop-only fencing | One orchestrator serves both modes; disabling autoheal removes only Start. Witness, active job, Stop/Start budgets, and blocked state are shared. | Stop-only rejects an unready witness, does not stop a second node, and cannot exceed 3 Stops/hour. |
| R2: inspect prevents a clean restart without Stop | Inspect does not change fence_state. Only a transactional Stop reservation blocks rotation; generation is checked before the call. | A Power error or clean restart between inspect and Stop neither triggers Stop nor blocks a new generation. |
| R3: rollout races autoheal | Durable cluster maintenance, mutual exclusion with recovery, and EC2 replacement binding after terminated. Lock expiry does not release the lock. | PostgreSQL integration: expired maintenance blocks Stop; stale scopes and competing operators are rejected. |

**Controlled recovery from blocked** uses resume/resolve with exact generation,
operation ID/revision, cloud observation, a quiescence guard, and durable request
receipts. Budgets are not reset; uncertain slots are not deleted.
The full contract and limitations are in [RECOVERY.md](RECOVERY.md).

## Residual risks and further improvements

- Readiness checks management/PID. Add separate bounded probes for TUN, DNS,
  forwarding, and selected network paths; a shared outage must not authorize
  cascading node stops.
- Losing every witness prevents new Stops. Expired maintenance also retains the
  cluster lock. Automation stops safely, but an operator and verified alert
  delivery are required.
- Public, agent and recovery Lambda entrypoints are separate. Deploy them with
  separate IAM roles and PostgreSQL roles; only recovery receives EC2 power
  permissions. Recovery independently checks node and witness conditions.
  Verify deployment grants against [component isolation](LAMBDA_ISOLATION.md);
  shared credentials would defeat that isolation.
- Cloud APIs have asynchronous transitions and eventual consistency.
  A database lock or SDK timeout does not prove EC2 operation completion.
  Local mocks cover lost responses and unknown/transitional states, but not
  every delay in the real control plane.
- Log alarms report transitions rather than persistent incident state.
  Add state-based monitoring and verify notifications. Use CloudTrail Lambda
  data events to audit operator identity; a request reason alone is not identity.
- Forced Stop may damage local files. Verify release/configuration and deployment
  health before returning the node to service.
- VPN server identity verification, independent SAML/XMLDSig review, key revocation
  and rotation, and provenance/SBOM remain: [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Legacy implementation remnants

- Duplicate stop-only orchestration has been removed. The provider contract now
  separates Power observation from explicit Stop; other VM adapters must implement it.
- In-place VPN renewal is absent. The renewal field remains only in negative
  tests and a checksum-protected historical migration; migration 006 drops the column.
- A single group_pools[].cidr, local controller/backend, and allowlist mode remain
  explicit supported modes, not hidden legacy implementations.
- Migrations 001–006 are unchanged. Migration 007 introduces recovery changes;
  legacy inspect is unblocked only if Stop could not yet have been reserved.
  Uncertain legacy Stops conservatively reserve an hourly budget entry.

## Verification

Builds and local unit/race/vet, PostgreSQL 18 integration, and security checks are
described in [BUILD.md](../BUILD.md). Recovery tests run under regular
`make integration`; no separate Go audit build tag is needed.
`TestFencingRegressionIntegration`, `TestOperatorRecoveryIntegration`,
`TestAutomaticRecoveryIntegration`, and `TestSessionLimitsAndFencingIntegration`
check the intended guarantees, rather than reproducing old defects.

Local tests do not exercise real cloud Stop/Start operations or deployment
rolling updates. Verify them in an isolated deployment before production.
