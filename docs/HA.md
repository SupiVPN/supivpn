# SupiVPN active-active cluster

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Nodes accept VPN connections through a shared UDP endpoint. With the optional
TCP fallback available since v0.9.0, the same public name also exposes TCP/443.
TCP remains disabled by default. Controllers use
PostgreSQL for SAML requests, decisions, and replay protection.
OpenVPN sessions and IP leases remain local to each node.

```mermaid
flowchart TB
    Client["OpenVPN client"] --> LB["UDP + optional TCP load balancer"]
    LB --> A["Node A: one agent, UDP + optional TCP"]
    LB --> B["Node B: one agent, UDP + optional TCP"]
    Browser["Browser"] <-->|SAML| IdP["SAML IdP"]
    Browser <--> HTTPS["HTTPS endpoint"]
    HTTPS --> Controller["Controllers: VM or Lambda"]
    A -->|Authenticated API| Controller
    B -->|Authenticated API| Controller
    Controller <--> DB["PostgreSQL: shared writer"]
    Keys["Shared wrapping key"] --> A
    Keys --> B
    Keys --> Controller
    A <-->|Node A CIDR| Resources["Private resources: group CIDR ACLs"]
    B <-->|Node B CIDR| Resources
```

Cloud load balancing, subnet layout, routes, and key delivery are deployment
responsibilities. AWS NLB/EC2/RDS is one option; runtime does not discover
accounts, zones, or route tables itself.

## UDP and TCP in an HA deployment

Transport fallback and node failover are separate operations. A generated
profile tries UDP on the shared endpoint first, then TCP/443 on the same name.
It does not enumerate individual nodes. The load balancer chooses a healthy
backend for each new flow; TCP need not select the node used by the previous
UDP flow. DNS with multiple addresses alone does not provide readiness checks
or deterministic failover timing.

When enabling TCP, configure both listeners on every participating node before
advertising TCP in newly issued profiles. Configure UDP and TCP forwarding and
firewalls independently. Forward encrypted OpenVPN traffic without TLS
termination: TCP/443 carries OpenVPN, not HTTPS. All targets must accept the
profile's exact verified server name, trusted CA and wrapping key and use the
same profile registry and SAML identity configuration.

Each node still has one agent, generation, lease and address allocator. UDP and
TCP share that node's complete group pools; they do not divide them again.
Different nodes **must retain non-overlapping pools**. For example, node A can
use its whole /25 for either transport, while node B uses its different /25.
Local /32 routes select a node's UDP or TCP TUN; upstream node-CIDR return routes
do not change. See [transport setup](TRANSPORTS.md) for the host configuration.

Use the node's `/readyz` for both transport target sets. When TCP is configured,
readiness requires both OpenVPN processes and the shared control path. A broken
management connection makes the whole node unavailable; the service manager
must stop both daemons before restarting that node's agent generation. Do not
keep one daemon accepting tunnels behind a stale generation. This intentionally
trades independent transport availability for trustworthy session accounting.

The three-second profile timeout bounds an unresponsive endpoint attempt, not
HA recovery. Established-tunnel detection, load-balancer health and flow expiry,
DNS, safe release of a previous session slot and SAML/MFA add their own delays.
Never release another node's session just because the client tried TCP. Until a
disconnect, clean generation replacement or fencing proves the old session is
gone, a connection limit may correctly prevent the replacement connection.

Existing bound UDP-only profiles keep working through the UDP listener. They
gain no TCP fallback automatically. During an upgrade, preserve the original
UDP port and trust material; do not remove that listener when enabling TCP.

## Node count and group expansion

Calculate addressing before starting agents. For N nodes and desired reserve R,
the slot count is `2 ^ ceil(log2(max(N, R)))`.
Split every parent group CIDR into that many equal subnets.
Use the first N slots and retain the rest as spare capacity.

| Nodes | Slots without extra reserve | /24 partition |
| --- | --- | --- |
| 2 | 2 | Two /25 subnets |
| 3 | 4 | Three /26 subnets and one spare /26 |
| 4 | 4 | Four /26 subnets |
| 5-8 | 8 | /27 per node; unused slots are reserved |

Reserve four slots initially for future growth from two to four nodes:
existing /26 subnets remain stable within that reserve.
Without a reserve, expanding from two to three nodes resizes existing subnets.
Reducing the node count must not silently change addressing either.

Illustrative example for two nodes:

| Group | Priority | Parent CIDR | Node A | Node B |
| --- | --- | --- | --- | --- |
| operations-vpn | 10 | 10.200.0.0/24 | 10.200.0.0/25 | 10.200.0.128/25 |
| engineering-vpn | 20 | 10.200.1.0/24 | 10.200.1.0/25 | 10.200.1.128/25 |

Expand a group with another parent CIDR partitioned by the same scheme.
Each agent receives the calculated `group_pools[].cidrs` for its node.
It tries pools in list order and rejects allocation when all are full.
Address exhaustion never moves a user to a lower-priority group.

Runtime also accepts the legacy singular `cidr` field, mutually exclusive with
`cidrs`. Network/broadcast addresses and the TUN gateway are never assigned.
Equal CIDR sizes do not necessarily provide equal usable capacity:
the slot containing the gateway reserves one additional address.

Deployment verifies:

- No overlaps between any groups/nodes, private destinations, or environment networks.
- Pools fit inside the configured TUN network and each subnet is large enough.
- Stable ordering of node slots and parent CIDRs.
- Enough available zones and subnets for the requested node count.
- Load balancing, routing, and egress coverage for every zone.

The agent neither creates VMs nor discovers available AZs.
One-node-per-AZ placement and zone availability checks belong to infrastructure tooling.

## Return routes

Within the VPN network, route every node CIDR to the corresponding node interface.
Connected networks may send an aggregate route through a transit router to the
VPN network. Check both directions and preserve group IPs wherever access
depends on them.

In AWS, this can be node CIDR -> ENI and aggregate -> Transit Gateway.
Other platforms use their own routes/next hops.
Route count grows with route tables, nodes, and group CIDRs; check quotas.

Configure Internet SNAT separately. Full tunnel routing and DNS are described in
[node requirements](HOST.md#full-tunnel).
If clients use the tunnel gateway for DNS, the forwarder must be ready on every node.

## Failure behavior

The load balancer checks node readiness. After tunnel loss, the client reconnects
to the same endpoint. Another node performs a new SAML login and assigns an IP
from its own pool. Existing SSH/TCP sessions are lost.
No manual profile switch is required when endpoint, TLS trust, and wrapping key agree.

The load balancer does not transfer OpenVPN state or leases between nodes.
The old pool's return route is not transferred either; the new IP has its own route.
Recovery time depends on keepalive, health checks, flow tracking, and the IdP.
An occupied cluster slot is not freed solely because its lease/session times out:
confirmed disconnect, a clean new generation, or fencing is required.
EC2 stop/start recovery can add minutes or enter blocked.
See [docs/RECOVERY.md](RECOVERY.md) and residual risks in
[docs/SECURITY_REVIEW.md](SECURITY_REVIEW.md). A local test with short timers does not
establish a production RTO.

## State and isolation boundaries

- `node_id + generation + CID + KID` isolates pending requests and decisions.
- UDP and TCP client IDs are distinguished inside that node scope. Preserve
  the full signed 64-bit CID in APIs and operational queries; do not round it
  through a floating-point number or compare raw OpenVPN CIDs across daemons.
- Node identity comes from verified transport; arbitrary JSON cannot override it.
- Agent generations, management sockets, and leases are not copied between nodes.
- The wrapping key is shared; losing or changing it requires profile reissuance.
- Connection limits and each group's capacity must tolerate node failure.
  Transport load balancing does not account for exhaustion of an individual group's pool.
- Automatic VM replacement and rolling updates belong to deployment, not SupiVPN runtime.

## Scaling

1. Prepare zones, subnets, the load balancer, egress, and new-node routes.
2. Calculate pools; check non-overlap and spare capacity.
3. If existing subnets change, stop issuing old leases before changing routes:
   an old address could move into another node's new slot.
4. Deliver configuration, the key, and node identity mappings; check readiness.
5. Allow new nodes to accept clients and verify routing and failover.

## Checks

See [GROUPS.md](GROUPS.md) for adding/removing groups across agent revisions,
local test coverage, and removal limitations.

- Login on each node: correct group and an IP from its local pool.
- Multiple groups: explicit priority wins; no permitted group means rejection.
- Additional CIDR: allocation continues in the next pool after the first fills.
- A previously issued profile works on all nodes and after VM replacement with the same key.
- Node failure: automatic reconnect, new SAML login, and another pool's IP.
- With TCP enabled: UDP preferred, blocked UDP falls back to TCP, and a shared
  profile works when the two transports reach different nodes.
- The same profile's owner, blocked state and user connection limit are enforced
  across all nodes and transports. A transport switch cannot bypass them.
- Stop either OpenVPN daemon: the entire node becomes unready, both daemons
  stop, and another node remains usable. Check both load-balancer target sets.
- Private resources see the group IP; test allowed and denied ports.
- Full tunnel routing, DNS, controller HTTPS, and Internet access work after reconnect.
- PostgreSQL unavailability blocks new authorizations; recovery needs no controller restart.

Local Go/PG tests check node isolation and shared state.
The [native OpenVPN suite](../testdata/openvpn/README.md) checks a real tunnel
and reconnection between two daemons. Cloud load balancing, routes, the IdP,
and client UI require separate acceptance tests.
