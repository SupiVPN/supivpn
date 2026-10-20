# Fencing, maintenance, and operator recovery

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The recovery state machine was introduced in PostgreSQL schema **7**.
Schema **9** isolates AWS public, agent and recovery database privileges.
The [recovery Lambda](LAMBDA_ISOLATION.md) alone owns power permissions and runs
from its scheduled rule; agent heartbeat no longer advances recovery. One orchestrator uses `postgres.Fencer`
(Managed/Power/Stop); `RecoveryDriver` additionally permits Start.
`automatic_recovery=false` disables only Start: all fencing guards remain.

## Guarantees

- One active recovery **or** maintenance operation across the cluster.
  A shared PostgreSQL advisory lock coordinates claims, power reservations,
  and operator changes; database locks are not held during cloud API calls.
  A busy lock defers the background step until the next tick; operator mutations
  return conflict and require another status check.
- Stop requires another ready node: healthy ≥30 seconds, lease remaining >30 seconds.
  Shared outages cannot authorize Stop. Readiness currently checks management/PID,
  not the entire network path.
- At most **3 Stops and 3 Starts per cluster per rolling hour**, and 3 Stops per cycle.
  Attempts are recorded **before** API calls; failed/unknown replies consume budget.
  Cooldown: 30 seconds; cycle deadline: 10 minutes. Operators do not reset time budgets.
- Inspect only reads power. Read failure, witness loss, or clean generation change
  before the first Stop reservation ends observation while allowing clean restart.
  The reservation itself sets `fence_state=stopping` under a node row lock and
  blocks rotation.
- Stop requires separate `stopped/terminated` confirmation.
  A successful HTTP call or `stopping` state does not release slots.
  Start requires the controller's own Stop reservation and observed stopped state;
  such a stop may recover without a witness. Nodes stopped elsewhere are not
  automatically started.
- After Start, require running, a **new generation**, and healthy ≥30 seconds.
  Deadline/budget exhaustion after reservation blocks the job and prevents new
  automatic stops across the cluster.
- Power uses a bounded context. Reservations retain `inflight_until` for
  30 seconds, longer than the 3-second reconciliation step. This guards against
  an unfinished worker call; it **does not prove** completion of the provider's
  asynchronous operation. Power observation is required for that.
- Core never invokes itself recursively. Heartbeat and fallback scheduler each
  perform one bounded step. The AWS driver limits Stop/Start to current instance
  IDs and rejects hibernation; a missing VM/Describe error does not mean stopped.

## Maintenance

Before drain/service shutdown, deployment calls `maintenance-begin`.
Any active/blocked recovery or unfinished power reservation prevents entry.
The lock contains operation ID, node ID, initial generation, and reason.
It neither changes slots nor stops heartbeat.

While held, the lock pauses automatic power operations across the cluster.
Its 30-minute lifetime limits new rollout steps **but does not release the lock**.
Expiry requires operator renewal or safe completion.
This deliberately may delay recovery of another failed node.

`maintenance-check` verifies ID, target, and expiry before each next action.
`maintenance-renew` extends the same lock by 30 minutes.
`maintenance-end` requires running and 30 seconds of stable health on the current
node. After failed work, restoring the previous healthy state permits completion
with the same generation.

For EC2 replacement, `maintenance-replace` binds **one** new node only after the
previous node is confirmed `terminated`. After binding, check/end/renew accept
only the new node. Failed recovery retains the lock for the operator;
time never completes it automatically.

## Recovery from blocked

First read status and check reason, generation, operation ID, revision, budgets,
power, and any unfinished rollout. Mutations supply exact `expected_generation`,
`recovery_id`, `expected_revision`, a new `request_id` (32–128 characters),
and a short non-secret `reason`.

- `recovery-resume`: permits the next bounded recovery cycle.
  Running after an uncertain Stop requires a witness and remaining budgets;
  rotation stays blocked. Confirmed stopped may proceed to Start when enabled
  and within budget.
- `recovery-resolve`: closes an incident only after stopped/terminated or a
  running, stably healthy **new** generation.
  Observation may be cancelled if Stop was never reserved; cancellation itself
  does not release slots.
- Both reject stale snapshots, active maintenance/another recovery, unfinished
  reservations, and unknown EC2 state.
- Idempotent retries use **the same request ID and payload**.
  A different payload with the same ID is rejected; retrying a committed request
  creates no second attempt. A new recovery operation ID invalidates previous
  confirmations. Generation tables, grants, and time budgets are not cleared.

## Transport and verification limits

AWS deployment enables `SUPIVPN_OPERATOR_CONTROL=1` and uses direct IAM-authorized
InvokeFunction on the controller's live alias with envelope
`source=supivpn.operator.v1`. There are no public operator HTTP routes.
API Gateway body/headers do not become top-level envelopes; the decoder rejects
extra/duplicate fields. The agent role explicitly denies direct invocation.

InvokeFunction is an administrative permission. Core logs action, node, request
ID, and reason; these do not establish operator identity.
Deployment must configure CloudTrail Lambda data events for IAM principal auditing.
VM deployment may call the same Store.Operate through its own privileged transport;
a ready-made VM operator listener is not yet available.

Local PostgreSQL 18/race tests cover guards/CAS/idempotency, uncertain replies,
shared outages, budgets, maintenance expiry, replacement binding, and controller
concurrency. AWS SDK calls are mocked: real EC2 transitions, eventual consistency,
and end-to-end rollout require deployment acceptance tests.
Unknown provider state never authorizes SQL reset.

Session accounting: [SESSIONS.md](SESSIONS.md).
Current risks: [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
