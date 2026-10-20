# SupiVPN VPN node

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

A node runs OpenVPN Community 2.7.8 and the `supivpn` Go agent.
This document defines the deployment contract; VM creation, systemd services,
firewall rules, and DNS belong to the operator's infrastructure.

For the 2.7.8 transition, see the [upgrade review and contract](OPENVPN_UPGRADE.md).
The OpenVPN package must be updated separately from the SupiVPN release bundle.

## Processes and files

- Install OpenVPN 2.7.8 and the built Linux binary `local/arm64/supivpn`.
- Start from [server.conf.example](../examples/server.conf.example):
  `topology subnet`, `server ... nopool`, `management-client-auth`,
  `management-hold`, `verify-client-cert none`, and `tls-crypt-v2`.
- The agent opens the management Unix socket before OpenVPN starts.
  Restrict access to the socket, agent state, and keys to the relevant processes.
- The adjacent `operator.sock` supports manual username-based disconnect:
  agent-owned directory mode 0700, socket mode 0600, and peer UID verification.
  Supply `idp_metadata` with the controller's issuer even in remote mode.
  See the [operator contract](REVOCATION.md).
- Configure `learn-address` to use the same agent: it verifies the IP-to-CID binding.
- Supply the TLS cert/key/chain and wrapping key. Any suitable secret delivery
  mechanism may refresh certificates; the application does not require Vault.
- Install the profile CLI only where key bootstrap or local issuance is needed.
- Provision the agent-owned log directory (0750) for the default
  `/var/log/supivpn/agent.jsonl`, or explicitly select stderr logging.
  Configure collection/retention for native OpenVPN and the service journal
  separately: [logging contract](LOGGING.md).

Paths such as `/etc/supivpn`, `/var/lib/supivpn`, and `/run/supivpn` are example
conventions. Keep them consistent across agent/OpenVPN configuration and services.
The [agent example](../examples/config.example.json) is isolated and does not
configure production routes, full tunnel routing, or DNS.

## Controller and addressing

Cluster agents use a shared remote controller; local in-memory mode is intended
for isolated tests. Transport is IAM/SigV4 to API Gateway or a Unix socket to a
VM controller. See [configuration and API](CONTROLLER_API.md).

All nodes use consistent group names and priorities. Each node receives its own
`group_pools[].cidrs`, disjoint from other nodes' pools. `vpn_network` covers the
local pools and matches OpenVPN's TUN configuration. OpenVPN does not allocate
from a dynamic pool: the agent supplies `ifconfig-push`.
See [pool allocation and scaling](HA.md#node-count-and-group-expansion).

## Routing and isolation

Access to private networks requires IPv4 forwarding, client route pushes,
a local firewall, and routes in both directions.
Preserve the group source IP when resource access is based on group CIDRs.
In AWS, disable source/destination checking on the routing node.

Each node CIDR's return route must point to that node's network interface.
Remote networks may use an aggregate route to the VPN network, which then routes
by node CIDR. Resource SGs/firewalls allow only the required ports from every CIDR
of the corresponding group.

The firewall must reject source IPs outside the local node's pools, unauthorized
VPN-to-VPN traffic, and access to cloud metadata services. Access to services on
the node is configured separately. The examples in this checkout do not create these rules.

## Full tunnel

Full tunnel routing requires client `redirect-gateway` options, forwarding,
Internet SNAT, and working node egress. Exclude private destinations that need
group CIDR authorization from SNAT.
A private VM may need a NAT gateway or another egress router.

For IPv4-only tunnels, configure supported clients to block bypass IPv6 traffic
and verify this separately. Changing the number of zones must not leave all
nodes dependent on a single egress path.

## Client DNS through the local node

The TUN gateway can be advertised as client DNS. A local forwarder listens only
on the required addresses and forwards to operator-selected upstreams.
Restrict UDP/TCP 53 access to client pools; a public recursive resolver is unnecessary.

If split DNS or a private wildcard shadows the controller's public HTTPS name,
forward only that hostname to public DNS. Other private names must continue to
resolve through private upstreams. Test node system DNS and client DNS separately.

## Readiness and lifecycle

The UDP load balancer uses the agent's HTTPS `/readyz`, which checks OpenVPN
initialization and the management connection. The deployment defines ports,
intervals, thresholds, and access rules. Check controller readiness separately.

Restarting the agent or changing addressing may disconnect tunnels.
Do not copy agent generations or leases to another node.
Restore the same wrapping key on replacement nodes and update their verified
identity in the controller.
See [key lifecycle](TLS_CRYPT_V2.md) and [HA checks](HA.md#checks).
