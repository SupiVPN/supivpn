# Application logging

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

SupiVPN writes one JSON object per line using Go's standard `log/slog`.
No network log exporter or object storage integration is included. A deployment
may collect files or standard streams independently of the VPN service.

## Destinations and defaults

| Executable | Default destination | Component |
| --- | --- | --- |
| `supivpn` service | `/var/log/supivpn/agent.jsonl` | `agent` |
| `supivpn-controller` VM service | `/var/log/supivpn/controller.jsonl` | `controller` |
| Public Lambda | stderr | `public` |
| Agent API Lambda | stderr | `agent_api` |
| Recovery/operator Lambda | stderr | `recovery` |
| Migrator, profile and packaging commands | stderr | `migrate`, `profile`, `package`, `release_manifest` |

Add the optional `logging` object to the agent or controller configuration.
Recovery Lambda accepts it in `SUPIVPN_RECOVERY_JSON`; HTTP Lambdas accept it
in their existing controller JSON configuration. No new environment variables
are required. Examples show all file defaults:

```json
{
  "logging": {
    "output": "file",
    "file": "/var/log/supivpn/agent.jsonl",
    "retention_days": 7,
    "max_size_mb": 10,
    "max_files": 10
  }
}
```

The other modes are `{"logging":{"output":"stderr"}}` and
`{"logging":{"output":"stdout"}}`. Lambda supports only these stream modes;
its temporary filesystem is not a durable logging destination. CLI tools
always use stderr. Operator protocol responses remain JSON on stdout;
help/usage output is separate from operational logs.

For file mode, omitted or zero `max_size_mb`/`max_files` use 10/10.
Allowed explicit values are 1..1024 MiB and 1..1000 archived files.
Omitted/null `retention_days` uses 7; explicit 0 disables age deletion but
keeps size/count limits. Positive values are 1..3650 days. Stream modes reject
file/retention settings rather than silently ignoring them. There is no runtime
log-level switch that can suppress security events.

## Files, rotation and failures

Provision the destination directory before service startup. It must belong to
the service UID, have no group-write or other-user permissions, and must not
itself be a symlink. Mode 0750 allows a collector group to traverse it; 0700
is suitable for collection by the service UID or root. Ancestor directories
must be trusted and must not be writable by untrusted users.

Files are created with mode 0640, further restricted by the service umask.
Existing files must be regular, owned by the service UID, without execute,
group-write or other-user permissions, and have one hard link. Symlinks and
special files are refused. Use different directories if the agent and VM
controller run as different UIDs. Paths must be absolute and clean; filenames
must be simple identifiers ending in `.jsonl`.

A process lock (`.agent.jsonl.lock` or `.controller.jsonl.lock`) prevents
multiple writers to one destination. Do not remove lock files while a service
is running. No external logrotate/copytruncate operation should target these
files: SupiVPN owns rotation.

Rotation occurs before a record would exceed the size limit and at the next
UTC day boundary. A maintenance timer checks once per minute, including when
there are no events. Startup also performs rotation/pruning. Archives use:

```text
agent.<UTC last-write timestamp>.<random suffix>.jsonl
controller.<UTC last-write timestamp>.<random suffix>.jsonl
```

For example, a timestamp has the form `20261015T123456.123456789Z`.
Each record stays on one physical line; there is no compression or copytruncate.
Keep the active file plus at most `max_files` archives. Archive age is measured
from the last write in that file; restarting does not reset its age.
It is not an exact per-record deletion deadline. Daily
rotation means a record can predate its archive by up to a day. When both age
and count limits apply, the first limit reached removes the archive. With
defaults, steady-state application storage is at most approximately 110 MiB
per service (one active file plus ten archives). Older files created under
larger limits are not rewritten when reducing configuration limits.

Startup fails if file logging cannot be initialized, including an unsafe path
or another writer. After startup, a write/rotation/pruning error emits
`logging.output_failed` once to stderr and sends subsequent application records
there until restart. It does not terminate the VPN solely because logging
failed. Monitor this fallback stream and local disk space.

Writes are synchronous to the local file without per-event fsync. This is not
a lossless or tamper-proof audit ledger: disk/kernel failure, process crashes,
node destruction, or collector lag beyond retention may lose records. A slow
filesystem can delay writes. Do not place the active log on a network mount.
The fallback stream needs its own retention and collection.

## Collection contract

| Source | What to collect |
| --- | --- |
| Agent file mode | `/var/log/supivpn/agent*.jsonl` |
| VM controller file mode | `/var/log/supivpn/controller*.jsonl` |
| Service stderr/stdout | Service manager journal/container stream, including startup errors and file-output failures |
| Three Lambda functions | Each function's CloudWatch Logs group, sourced from stderr/stdout |
| Native OpenVPN | Its existing journal/syslog/explicit log destination; separate plain-text stream |

Adjust globs for a configured filename. Include both active and rotated files,
exclude hidden lock files, and give the collector read/traverse access only.
If umask removes group-read access, explicitly arrange a safe service group/
umask or ACL policy; do not make logs world-readable.

The collector should track file identity and offsets across rename, persist
checkpoints, finish reading renamed files, and use a bounded retry buffer.
Test a collector restart and a service rotation together; avoid replaying all
archives on every restart. Enrich records with node/instance ID, environment
and service unit in collector metadata without overwriting application fields.
Keep transport credentials outside SupiVPN's logging configuration.

Local retention only governs application files. Configure journal and
CloudWatch retention independently (7 days is the suggested deployment
default), and separately limit collector buffers and destination retention.
An unreachable collector must not hold up service startup.

For Lambda, use JSON log format for platform logs and preserve INFO application
events. SupiVPN emits JSON itself; AWS documents that already-JSON logs are
not double-encoded. Platform events have a different schema:
[AWS log format documentation](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-logformat.html).
Do not classify platform `REPORT`/runtime records as SupiVPN events.

OpenVPN is a separate executable: its native logs are not converted to this
schema. Do not raise its verbosity or export raw management/debug traces just
to obtain application audit fields.

## Schema and event selection

```json
{"timestamp":"2026-10-15T12:00:00Z","level":"INFO","message":"VPN tunnel established","schema_version":1,"service":"supivpn","component":"agent","event":"vpn.tunnel_established","trace_id":"eea51fe908d8e94e6dffc2411ebb05ea","cid":12,"kid":0,"node_id":"node-a","generation":"generation-a","username":"alice","group_name":"admins-vpn","address":"10.200.0.129","peer_ip":"198.51.100.24","peer_port":54321}
```

Always present: `timestamp` (UTC RFC3339Nano), `level`, `message`,
`schema_version`, `service`, `component`, `event`.
Correlate on `event` and typed fields, not message wording. The JSON schema
version is independent of the database schema and release version.

Optional fields depend on the event: `trace_id`, `cid`, `kid`, `node_id`, `generation`,
`username`, `group_name`, `address`, `peer_ip`, `peer_port`, `purpose`, `outcome`, `reason`,
`operation`, `status`, `phase`, `action`, `operator_request_id`, `client_version`,
`client_platform`, `establishment_ms`, `duration_seconds`, `bytes_received`,
`bytes_sent`, `disconnect_source`, `disconnect_reason`.
Lambda records additionally use the platform invocation's `request_id` when
available. Client headers cannot set it. Invocation context is reset between
requests. A flow's `trace_id` is shared across components; `request_id` still
identifies just one Lambda invocation and must not replace it.

| Events | Meaning / severity |
| --- | --- |
| `vpn.connection_requested`, `vpn.tls_reauthenticated` | Connection accepted for authentication, or existing session accepted a TLS rekey; INFO |
| `vpn.tunnel_established`, `vpn.disconnected` | Verified tunnel identity, VPN address and last observed peer endpoint; INFO |
| `vpn.browser_auth_requested`, `vpn.authorization_applied`, `vpn.session_expired` | VPN authentication/session lifecycle; INFO |
| `vpn.authentication_refused`, `vpn.authorization_denied` | Local capacity/authorization rejection; WARN |
| `saml.login_started`, `saml.authorization_decided` | Browser login purpose and decision; denied decisions are WARN |
| `saml.request_refused`, `saml.response_refused` | Invalid/expired browser login request, or signature/assertion validation refused; WARN |
| `agent.login_registered`, `agent.decision_delivered` | Connection registered, or a completed decision returned to its bound agent; INFO |
| `agent.decision_acknowledged`, `agent.connection_cancelled` | Agent result or disconnect recorded in PostgreSQL; INFO |
| `profile.issued`, `profile.issue_failed` | Profile generated (not confirmed downloaded), or generation failed |
| `controller.ready`, `agent.https_ready`, `agent.management_ready` | Startup milestones; INFO |
| `controller.request_retry`, `controller.request_refused` | Remote operation/status, without payload or error text; WARN |
| `controller.lease_expired`, `controller.generation_rejected` | Agent safety shutdown conditions; ERROR |
| `controller.ack_expired`, `controller.decision_rejected` | Expired/invalid authorization acknowledgement; WARN |
| `maintenance.expired` | Maintenance expired while still retained; ERROR |
| `recovery.transition` | Recovery phase/reason; blocked is ERROR, other phases INFO |
| `operator.action_completed`, `operator.tunnel_drop_requested` | Operator action audit; INFO / WARN |
| `session.unlimited_configured` | Unlimited-session security warning; WARN |
| `logging.output_failed` | File sink failure and stderr fallback; ERROR |
| `component.initialization_failed`, `component.stopped`, `configuration.refused`, `invocation.failed` | Runtime failure; ERROR |
| `operator.request_failed`, `database.migration_failed`, `profile.issue_failed`, `package.failed`, `manifest.failed` | CLI/operation failure; ERROR |
| `database.schema_current`, `profile.file_ready` | CLI completion; INFO |

Successful heartbeats and pending fetch polls do not create a log per request.
Returning a completed decision does create `agent.decision_delivered`, including
retries before acknowledgement. Successful idempotent ACK/cancel retries can
also repeat events with the same trace ID; these are not new connections.
These events are not a complete HTTP access log or a list of every rejected
network packet. API/front-proxy metrics remain necessary.

### VPN address and observed peer endpoint

`address` remains the IPv4 address allocated inside the VPN. Starting with
v0.4.4, authorized tunnel establishment/disconnection events can additionally
include `peer_ip` (canonical IPv4 or IPv6, without a port) and `peer_port`
(an integer from 1 to 65535). These optional fields are an additive extension
of JSON schema version 1; collectors must tolerate their absence on older nodes.

The agent reads only OpenVPN's daemon-generated `untrusted_ip`/`untrusted_ip6`
and `untrusted_port` during CONNECT/REAUTH, and `trusted_ip`/`trusted_ip6` and
`trusted_port` during ESTABLISHED/DISCONNECT. Values must form one valid,
unambiguous endpoint. Missing, malformed, duplicate or scoped-address values
are omitted without changing authentication or connection cleanup. Peer
information supplied through IV_/UV_ variables, browser headers and SAML
attributes cannot populate these fields. Pending, unauthenticated disconnects
omit them, as they omit `username`.

Each connection retains its last valid endpoint observation. Establishment,
successful reauthentication and disconnect notifications can update it. A
disconnect inferred from a complete status snapshot uses the cached endpoint;
status reconciliation still retains only CIDs. This is not continuous address
tracking. A CID reused by a later connection cannot inherit an old endpoint.
The authenticated SAML identity remains separate from this network metadata.

With NAT/CGNAT or a client-side proxy, this is the address and port visible to
OpenVPN, not necessarily a device's public or LAN address. Several users can
share one IP, and one user can change addresses. Never use it as an identity
or authorization input.

For an AWS Network Load Balancer forwarding directly to supported targets:

| Target group | Default endpoint observed by OpenVPN |
| --- | --- |
| UDP or TCP_UDP, instance/IP targets | Client source IP; preservation is mandatory |
| TCP, instance targets | Client source IP; preservation is enabled by default |
| TCP, IP targets | NLB source IP; enable `preserve_client_ip.enabled` to retain the client IP |

IP preservation requires a supported network path and address family. In
particular, IPv6-to-IPv4 translation and PrivateLink can replace the source
address, and Transit Gateway paths do not support preservation. The log reports
what OpenVPN actually observes; it cannot reconstruct an address removed upstream.
Do not enable PROXY protocol v2 on a target group without a receiver that parses
it; the current direct OpenVPN integration does not add such a receiver.
See [AWS client IP preservation and PROXY protocol requirements](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html).
Local native tests cover daemon endpoint delivery over TCP and UDP; they do not
constitute an AWS NLB deployment test.

### Establishment diagnostics and disconnect summaries

Starting with v0.4.5, `vpn.tunnel_established` can include:

| Field | Meaning |
| --- | --- |
| `client_version` | Initial CONNECT's `IV_VER`, a bounded printable ASCII label |
| `client_platform` | Initial CONNECT's `IV_PLAT`, a bounded platform identifier |
| `establishment_ms` | Agent-observed elapsed milliseconds from handling CONNECT to the first ESTABLISHED |

Client version/platform are self-reported diagnostics, not verified device
identity or proof of a secure client. They are optional and can be absent or
incorrect. Rekey events cannot replace the initial labels or reset the timer.
The establishment interval includes browser/SAML login and agent processing;
it is not network RTT. A missing start or backwards test/system clock omits the
interval. Fields are restricted to authorized establishment events.

`vpn.disconnected` includes `disconnect_source=management_event` for a daemon
DISCONNECT or `disconnect_source=status_snapshot` when a complete ordered status
snapshot confirms that the CID is gone. For example:

```json
{"event":"vpn.disconnected","cid":12,"disconnect_source":"management_event","disconnect_reason":"operator_requested","duration_seconds":7200,"bytes_received":125000,"bytes_sent":250000}
```

This abbreviated example omits the common envelope and identity fields.
Authorized DISCONNECT summaries can contain `duration_seconds` from OpenVPN's
`time_duration`, `bytes_received` from the client, and `bytes_sent` to the
client. These are OpenVPN's session/link counters, not application payload or
cloud billing totals. The daemon duration starts at client-instance creation,
so it can include authentication. Zero is a valid observation. Missing,
malformed, negative, overflowing or duplicate values are omitted individually.
They are unsigned 64-bit integers; consumers needing exact large counts must
avoid lossy floating-point parsing. No credential or complete environment block
is retained. See [OpenVPN environment variables](https://build.openvpn.net/man/openvpn-2.6/openvpn.8.html)
and [management notifications](https://openvpn.net/community-docs/management-interface.html).

If DISCONNECT is lost, status cleanup cannot recover its final duration or
byte totals; these fields remain absent. No zero, stale snapshot or local
estimate substitutes for a final daemon observation. Pending unauthenticated
disconnects omit these metrics, as they omit the verified identity. A removed
or reused CID cannot inherit earlier diagnostics, metrics or reasons.

`disconnect_reason` records the first known SupiVPN decision when present:

| Value | SupiVPN decision |
| --- | --- |
| `operator_requested` | An exact-user operator drop requested termination |
| `session_expired` | An authorized session's deadline expired |
| `pending_auth_expired` | A pending authentication deadline expired |
| `reauthentication_refused` | Rekey was refused for an ineligible tracked connection |
| `connection_limit` | Local authorization exceeded the user's connection limit |
| `invalid_groups_claim`, `no_vpn_group`, `pool_full` | Authorization or allocation was refused |
| `controller_refused` | The remote-controller path refused a pending login |

This is the agent's termination/refusal decision, not proof of the underlying
network cause. It survives status-based cleanup. Without such a decision the
reason is omitted; a network failure, a client clicking Disconnect and a lost
connection are not reliably distinguishable from DISCONNECT alone. No client
environment field can supply the reason or confirmation source.

All fields are additive within JSON schema version 1. Existing collectors must
tolerate their absence. They add no SQL/API fields or authorization policy.

## Flow correlation and future tracing

Starting with v0.3.0, each VPN connection has a `trace_id` shared by the agent,
public SAML controller and agent API. Filter application logs by this field to
follow CONNECT, browser authentication, the authorization decision, management
acknowledgement, tunnel establishment, TLS rekey, expiry/operator drop, and
disconnect/cancellation. The ID remains stable across controller replicas,
Lambda cold starts and retries. A new connection gets a new ID even if OpenVPN
reuses a CID or the same user reconnects. Profile download has its own flow;
the downloaded profile does not embed its ID or carry it into later VPN sessions.

The agent generates a random login ticket with 256 bits of entropy. After a
backend validates the corresponding login, components independently reconstruct
the same ID from the ticket or its stored SHA-256 hash:

```text
trace_id = lowercase_hex(first_16_bytes(
    SHA256("supivpn/login-trace/v1\x00" || SHA256(ticket))))
```

The separator is one zero byte and the inner hash is its 32 raw bytes. Keep this
derivation stable across versions. The extra hash, domain separation and
truncation avoid exposing either the bearer ticket or its database lookup hash.
The ID is correlation metadata only: it cannot authorize a request, fetch a
decision or look up a session through an API. No username, IP or timestamp is
used to construct it. No extra database column, query or protocol field is needed.

Incoming `traceparent`, `tracestate`, `baggage` and arbitrary logging attributes
cannot set the flow ID. A browser request is bound to it only after its backend
login/browser checks pass. Refusals before that point use a fresh request trace,
so an invalid request cannot join an existing session's log history. There is
no trace ID in redirect URLs, SAML assertions, cookies or client profiles.

Node-wide heartbeats, recovery and startup events do not belong to one VPN flow.
Use `node_id` and `generation` to relate them to affected sessions. Lambda
non-flow failures/recovery logs have an independent invocation trace; startup
and other unbound process events may omit `trace_id`. Native OpenVPN text logs
remain separate and do not acquire this field. Connection refusals before a
login is allocated can also omit it. This is application correlation, not a
complete packet or HTTP access log.

IDs use the nonzero 16-byte / 32-lowercase-hex representation defined by
[W3C Trace Context](https://www.w3.org/TR/trace-context/). A future OpenTelemetry
integration can reuse these bytes as its TraceId and add real spans to that
trace. The current release does not create spans, export traces or emit fake
`span_id`/`trace_flags` fields. Span context propagation, parenting, sampling
and export remain future work. The
[OpenTelemetry logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
allows a TraceId without a SpanId. A collector may map the validated hex field
to the OTLP log record's TraceId; it must not invent spans or sampling flags.

Preserve `trace_id` as a searchable exact string, not a numeric value or metric
label. Do not overwrite it with a proxy request ID or Lambda/X-Ray identifier.
Logs can arrive out of order; use timestamps and event names, not ingestion
order, to reconstruct the flow. Trace IDs enable correlation of access metadata,
so apply the same access restrictions and retention as the containing logs.

The v0.3.0 addition keeps JSON schema version 1, database schema 9 and release
bundle format 3. Configuration, API authorization and log destinations are
unchanged from v0.2.0. Mixed-version rolling updates work, with correlation gaps
where old components omit the field. Existing logs cannot be retroactively
assigned a reliable flow ID.

## Data protection and rollout

Only approved events and fields are emitted. Raw errors, URLs/query strings,
request/response bodies, SAML XML, RelayState/login tokens, cookies, credentials,
keys and arbitrary objects are excluded. Free-form operator reasons are not
logged; the protected operator receipt retains them.

Verified tunnel events include the exact decoded SAML NameID as `username`.
Unverified/pre-authorization events omit it. JSON escapes controls, quotes,
line separators and bidirectional controls. Log viewers must display strings
as data; decoding JSON must not turn embedded controls into new log entries.
Usernames, group names, VPN addresses and peer endpoints are personal/access
metadata: restrict read access and apply retention at every copy.

Version v0.2.0 introduced JSON logs and the VM default file destination. When
upgrading from an earlier version:
1. Provision writable private log directories and a collector, or explicitly
   choose stderr to retain journal-based collection.
2. Update filters/alarms to JSON events; allow old and new formats during a rolling
   deployment. In particular monitor `maintenance.expired`,
   `recovery.transition` with `phase=blocked`, `controller.lease_expired`,
   and `logging.output_failed`.
3. Verify allowed/denied SAML login, profile generation, tunnel disconnect,
   retention/rotation and fallback collection.
4. Keep native OpenVPN diagnostics separate from JSON parsing.

No database migration, API authorization change or release bundle format change
is required for logging or flow correlation. Binaries older than v0.2.0 reject
the `logging` configuration field, so a rollback to those versions must restore
the corresponding old configuration as well.
