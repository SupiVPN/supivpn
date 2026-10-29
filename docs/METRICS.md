# Prometheus metrics

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN). See LICENSE.

**Availability:** v0.10.0 and later. Upgrade before adding this configuration;
v0.9.x packages do not accept it. No database migration or bound-profile reissue
is required. Follow the [profile migration guide](PROFILE_BINDING.md#explicit-legacy-transition-through-v09x)
before upgrading a deployment that still uses unbound profiles.

Metrics are **disabled by default** in every component. An absent block,
`{}` or `{"enabled": false}` opens no metrics socket, reads no metrics TLS
files or bearer secret, and performs no metrics queries. To enable them,
set `metrics.enabled: true` and the adapter-specific settings below, then
restart the component. Disable with `enabled: false` and restart.

The exporter uses the Go standard library and Prometheus text format 0.0.4.
It has no new Go dependencies, external assets, sidecar or OpenVPN modifications.
Only GET is accepted; query strings and request bodies are rejected.

## VM and VPN-node agent

Add a top-level block to `/etc/supivpn/node/agent.json`:

```json
{
  "metrics": {
    "enabled": true,
    "listen": "127.0.0.1:9098",
    "tls_certificate": "/etc/supivpn/node/tls/crt.pem",
    "tls_chain": "/etc/supivpn/node/tls/chain.pem",
    "tls_private_key": "/etc/supivpn/node/tls/key.pem"
  }
}
```

Use the certificate paths provisioned on your host. The certificate must match
the DNS name that Prometheus verifies. A full-chain certificate can be used
without `tls_chain`. TLS 1.2 or newer is required; plaintext is never served.
The listen address must contain a literal IP and a port from 1024 through 65535.

The endpoint is `https://127.0.0.1:9098/metrics`. The existing public
login/health listener does not expose it. For a combined host, optionally add
the same block to `/etc/supivpn/controller/controller.json`, using a different
port such as `9099` and certificate paths readable by
`supivpn-controller`. This exports database gauges separately.

The minimal VM setup intentionally uses server-authenticated TLS without a
bearer token or client certificate. This is an accepted non-production setup:
restrict access to the monitoring network with a firewall. Anyone who can
reach that port can read aggregates, including configured group names. Change
the listen IP to the host's private monitoring address for a remote scraper;
the application does not open firewall ports or change DNS.

After editing, restart only the changed services in a maintenance window.
Restarting the node agent stops its paired OpenVPN daemons and disconnects
tunnels. Metrics configuration is not hot-reloaded. Do not rerun the initial
setup helper to change metrics.

Example Prometheus scrape configuration (use your actual certificate DNS name):

```yaml
scrape_configs:
  - job_name: supivpn-agent
    scheme: https
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 5s
    follow_redirects: false
    static_configs:
      - targets: ['127.0.0.1:9098']
    tls_config:
      ca_file: /etc/prometheus/supivpn-monitoring-ca.pem
      server_name: vpn.example.test
      min_version: TLS12
```

For a publicly trusted certificate, the system CA bundle can replace the private
CA file. Do not use `insecure_skip_verify`. A scrape with an untrusted
certificate or the wrong server name must fail.

The same agent endpoint applies to EC2 nodes using Lambda controllers:
the agent still observes the actual OpenVPN tunnels on the node.

## Public Lambda

Enable this only in the **public** controller Lambda configuration:

```json
{
  "metrics": {
    "enabled": true,
    "bearer_token_secret_arn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:metrics-scrape-Ab12Cd"
  }
}
```

Provision a dedicated random 32-byte token, encoded as exactly 43 unpadded
base64url characters. Store that string as the secret's raw `SecretString`,
without JSON wrapping or a trailing newline. Deliver the same token securely
to a file readable only by Prometheus. Do not reuse a database password,
SAML key, profile secret or Okta token; do not place it in a URL.

Grant the public Lambda execution role `secretsmanager:GetSecretValue`
on that one secret ARN. If using a customer-managed KMS key, grant the required
`kms:Decrypt` on that key with the appropriate Secrets Manager restrictions.
Do not grant these permissions to the agent or recovery Lambda.

The loader requests `AWSCURRENT`, validates the returned ARN/stage and token
format, and retains a SHA-256 digest for constant-time comparison. Invalid or
unavailable credentials prevent startup when metrics are enabled; there is no
unauthenticated fallback. The token is loaded once during initialization.
Rotation requires replacing/restarting every warm public Lambda execution
environment, then updating the Prometheus credential file. Until all old
environments are gone, the old token can remain accepted there. No automatic
Secrets Manager polling or two-token grace period is implemented.

Add the **exact** API Gateway route `GET /metrics` to the public Lambda
(or `GET /supivpn/metrics` when that is the configured `public_url` prefix).
Both HTTP API v2 and REST proxy adapters are supported. Keep the existing
API/account/stage/domain checks and scoped Lambda invocation permission.
Do not map this route to the IAM agent function, recovery function, a wildcard
proxy or a direct Lambda Function URL. The application validates the Bearer
header; a caller's SAML cookie is not authorization to scrape.

Keep gateway response caching off. Do not log Authorization headers, secrets
or entire request events. Apply route throttling suitable for the scrape
interval; unauthorized requests can still incur gateway/Lambda cost.
Normal cold-start initialization still opens the controller's database;
unauthorized requests never execute the metrics snapshot query.

```yaml
scrape_configs:
  - job_name: supivpn-controller
    scheme: https
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 10s
    follow_redirects: false
    static_configs:
      - targets: ['login.example.test']
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/supivpn-metrics
    tls_config:
      min_version: TLS12
```

This is native [Prometheus HTTP authentication](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).
A missing, wrong or duplicate token returns 401 before snapshot collection,
including cached snapshots. Metrics disabled returns 404 even if the gateway
route remains configured. The deployment does not create the secret, IAM
policy or API Gateway route automatically.

## Initial metric set

Agent counters reset on process restart; use `rate()` or `increase()`.
Group labels come only from validated configuration. There are no username,
email, IP, node ID, profile ID, Device ID, ticket, CID/KID or SAML labels.
Prometheus target labels identify a node; group names themselves remain
operator-controlled information.

| Metric | Type / labels | Meaning |
| --- | --- | --- |
| `supivpn_sessions_active` | Gauge, `group` | Established tunnels not yet confirmed disconnected, including closing tunnels. |
| `supivpn_sessions_total` | Counter, `group` | First ESTABLISHED event per tracked connection. Duplicate events and rekey do not add sessions. |
| `supivpn_disconnections_total` | Counter, `group` | Previously established tunnels confirmed absent by DISCONNECT or a management snapshot. Unknown disconnects are not invented events. |
| `supivpn_ip_pool_capacity` | Gauge, `group` | Actual usable configured addresses, excluding network, broadcast and gateway addresses. Multiple CIDRs are combined. |
| `supivpn_ip_pool_allocated` | Gauge, `group` | Addresses still held by pending/established/closing connections. UDP and TCP share this pool. |
| `supivpn_ip_allocation_failures_total` | Counter, `group` | Allocation refused because that group's pool was full. |
| `supivpn_openvpn_management_up` | Gauge | All configured management connections are attached and open. |
| `supivpn_openvpn_initialized` | Gauge | All configured daemons reported tunnel initialization. It does not prove end-to-end reachability. |
| `supivpn_controller_lease_remaining_seconds` | Gauge | Locally trusted lease time remaining; zero when absent or expired. |
| `supivpn_controller_requests_total` | Counter, `operation,result` | API calls including retries. Operations: rotate, heartbeat, register, fetch, ack, cancel. Results: success, retryable, refused, error. |
| `supivpn_controller_request_duration_seconds` | Histogram, `operation` | API latency with buckets 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10 seconds and +Inf. |
| `supivpn_controller_nodes` | Gauge, `state` | Shared database node counts: ready lease, expired lease, stopping, stopped. |
| `supivpn_controller_login_records` | Gauge, `state` | Retained pending, started, decided, acknowledged and cancelled rows. **Not live tunnel counts.** |
| `supivpn_controller_reserved_slots` | Gauge | Admission slots still occupied under the actual database admission rules. Expiry alone is not proof of disconnection. |
| `supivpn_controller_snapshot_timestamp_seconds` | Gauge | Completion time of the cached database snapshot. |

An API result of success is not proof of SAML authorization or tunnel
establishment. Management health is observed without issuing commands during
a scrape. Agent snapshots use a non-blocking lock; busy collection returns 503.
Database collection has a 1.5-second query deadline and one in-flight request
per process. Successful snapshots are cached for at most five seconds.
Expired cache entries are not returned after a database error; the scrape
fails instead of reporting healthy zeros. Large retained tables can make
aggregate scans time out; monitor collection failures and keep normal pruning
operational. No schema indexes or write privileges are added.

Do not sum controller gauges from replicas/Lambda instances reading the same
database. Scrape one stable controller URL per deployment. Agent gauges may
be summed across distinct nodes with non-overlapping pools; do not double-count
the same target through several scrape jobs. No per-instance Lambda event
counters are exported because cold starts and concurrency would make them
misleading.

## Initial alerts and checks

Start with these expressions, scoped by your deployment/job labels and with an
appropriate pending duration rather than alerting on a single failed scrape:

- `up{job="supivpn-agent"} == 0` and `up{job="supivpn-controller"} == 0`.
- `supivpn_openvpn_management_up == 0` or `supivpn_openvpn_initialized == 0`.
- `supivpn_ip_pool_allocated / supivpn_ip_pool_capacity > 0.9`.
- `increase(supivpn_ip_allocation_failures_total[5m]) > 0`.
- `sum by (instance, operation) (rate(supivpn_controller_requests_total{result!="success"}[5m])) > 0`.
- `supivpn_controller_nodes{state="expired"} > 0`.

Check that disabling metrics closes the VM listener or returns 404 in Lambda;
wrong/missing Lambda credentials return 401; correct scrapes return text with
HELP/TYPE lines. During a real disconnect, compare established tunnels with
allocated addresses and reserved slots instead of treating them as synonyms.

Traffic bytes, session duration distributions, per-user/device statistics,
fine-grained SAML denial reasons, recovery events, OS/process collectors and
dashboards are deferred. Use node_exporter for machine metrics. No management
reconnect counter is exposed: the current agent exits when management is lost.
