# VPN group policy and changes

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Groups are controller/agent configuration; membership comes from exact names in
a verified SAML assertion. IdP membership changes apply at the next login.
An active tunnel does not reread groups on heartbeat or TLS rekey.
Urgent revocation remains a [separate, unimplemented protocol](REVOCATION.md).

## Selection and policy example

The controller chooses **one** permitted group with the lowest numeric `priority`
among the memberships in the verified assertion. Both the SAML attribute-value
order and the order of entries in the runtime JSON are irrelevant. Priorities
must be unique non-negative integers; group names must be unique and match the
assertion exactly. A configured group that is absent from the assertion cannot win.
See [claim format and name rules](IDENTITY_PROVIDER.md#groups-claim).

The selected group determines address pools, session duration and connection
limit. SupiVPN does not merge group permissions or add their limits. Network
permissions are enforced by operator-defined firewall/ACL rules for the assigned
group CIDRs; SupiVPN does not infer allowed destinations from a group name.

The Debian helper accepts an ordered list of names and generates priorities
10, 20, 30, ... with equal-sized pools. That is a setup convenience. The runtime
supports explicit priorities, per-group overrides and multiple differently sized
pools. After initialization, edit the generated files as described in
[DEPLOYMENT.md](../DEPLOYMENT.md#customize-the-generated-configuration).

For a fresh node using `10.203.0.0/24`, the following **partial configuration**
gives admins two connections and one-hour sessions, while engineers inherit one
connection and twelve hours. Merge these fields into the existing files; retain
the generated TLS, database, profile and transport settings.

Controller, `/etc/supivpn/controller/controller.json`:

```json
{
  "saml_groups_attribute": "groups",
  "max_connections_per_user": 1,
  "session_seconds": 43200,
  "groups": [
    {"name": "admins-vpn", "priority": 10, "max_connections_per_user": 2, "session_seconds": 3600},
    {"name": "engineers-production-vpn", "priority": 20}
  ]
}
```

Agent, `/etc/supivpn/node/agent.json`, with the same policy:

```json
{
  "saml_groups_attribute": "groups",
  "max_connections_per_user": 1,
  "session_seconds": 43200,
  "vpn_network": "10.203.0.0/24",
  "group_pools": [
    {
      "group_name": "admins-vpn", "priority": 10,
      "max_connections_per_user": 2, "session_seconds": 3600,
      "cidrs": ["10.203.0.0/26", "10.203.0.64/26"]
    },
    {
      "group_name": "engineers-production-vpn", "priority": 20,
      "cidrs": ["10.203.0.128/25"]
    }
  ]
}
```

Use either `cidr` or `cidrs` for a group, never both. The agent tries the selected
group's CIDRs in order; if all are full, it rejects with `pool_full` and never
falls back to another group. Pools must fit inside the node's VPN network and
must not overlap each other, other nodes, client LANs or destination networks.
Gateway, network and broadcast addresses are not allocated. See
[pool allocation](IDENTITY_PROVIDER.md#pools) and [capacity planning](HA.md#node-count-and-group-expansion).
These are example CIDRs for a fresh deployment, not a pool migration procedure.

Connection limits are per verified user across the cluster, including other
groups and nodes, not a separate quota for each membership. Group overrides use
1–16 connections and 60–43200 seconds; omitted limits inherit global defaults.
A group `session_seconds: 0` explicitly removes the local deadline; it does not
mean inheritance. A signed IdP session deadline still applies. Review the
[session policy and unlimited-duration implications](SESSIONS.md#policy)
before choosing durations.

### Check your policy

| Test with the example above | Expected result |
| --- | --- |
| User belongs only to `engineers-production-vpn` | An engineer pool address; one connection and a maximum twelve-hour local session. |
| User belongs to both groups, in either SAML order | An admin pool address; two connections and a maximum one-hour local session. No engineer permissions are added. |
| User belongs to no configured group | Login/profile authorization is denied. |
| Admin attempts a third connection while two are active | The new attempt is denied; the existing sessions remain. |
| First admin pool is full | Allocation continues in the second admin pool; if both are full, the attempt is denied. Test exhaustion only in an isolated test environment. |
| Session reaches its local or earlier signed IdP deadline | Tunnel closes; reconnect requires fresh SAML authorization. |
| Each group accesses private resources | Allowed destinations/ports work; denied ones fail, and the destination sees the expected group source address. |

Use the [routed-network example](DEPLOYMENT_MANUAL.md#10-add-access-to-a-private-network)
to configure access rules and return routes for your actual CIDRs. Test positive
and negative access explicitly: an assigned address or successful readiness check
does not prove firewall isolation. Membership changes take effect at the next
login; they do not terminate an existing tunnel.

## Adding and removing groups

Adding groups requires non-overlapping CIDRs, routes/ACLs, agent configuration,
and controller policy. A new controller can select a new group before every
agent has its pool: an old agent rejects the request instead of assigning
another group's address. A denied ACK releases the global slot reservation,
so a later attempt on an updated node may succeed.
The load balancer cannot guarantee a suitable node until rollout completes.

After removing a group from the controller, the next SAML callback:

- Rejects the user if no permitted group remains.
- Selects another permitted group by priority if present in the signed assertion.

A callback initiated before the change uses the policy of the controller
currently handling it. This is not a cluster-wide policy epoch: an old controller
process still serving requests continues to use its old configuration.

**Important limitation:** replacing configuration does not invalidate a grant
already committed in PostgreSQL or revoke an active tunnel.
An old agent with the matching pool can still apply that grant.
An updated agent without the pool rejects it.
Rollback can restore old policy; it is not a revocation operation.

Pools and routes cannot safely be removed or reassigned to another group solely
because configuration changed. The required order is:
deny new grants -> invalidate pending grants -> terminate old sessions and
confirm disconnect/fencing -> remove routes/ACLs/pools.
This automatic lifecycle is not implemented yet. Until then, removing groups
from a running cluster needs a separate procedure or maintenance.
Validation rejects an empty group list; it is not a deny-all switch.

## Local tests

`internal/agent/group_lifecycle_integration_test.go` runs two agents with different
immutable configurations, fresh controller instances, two connection pools to
PostgreSQL 18, SAML responses signed by a temporary IdP, and the real HTTP/JSON
agent API. The harness supplies transport identity; OpenVPN management uses a pipe.
No AWS, external IdP, or real tunnel is required.

Scenarios:

- Add one/two groups: rejection before controller update, rejection on the old
  node, correct IP on an updated node, and unchanged groups remaining accessible.
- Remove one/two groups while browser logins are pending.
- Preserve priority among remaining groups.
- Old-node rejection frees the slot; changing groups cannot bypass an occupied slot.
- A new signed login after membership changes selects a new pool or rejects access.
- Rolling back to a narrower policy does not grant new access to a removed group.
- **Characterization of current limitations:** an active session survives group
  removal; an old agent still applies a committed grant.

The last checks document current behavior, not approval of it as secure
revocation. Replace them with tests of the new contract when implementing
revocation. Tests do not perform real node rollouts or prove safe route removal
or CIDR reuse.

Run from the product root with no other tests using the disposable database:

```sh
make postgres-start POSTGRES_PORT=55433
export SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55433/supivpn_test?sslmode=disable'
export SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1
make integration PKG=./internal/agent RUN=TestGroupLifecycleIntegration TEST_VERBOSE=-v
make postgres-stop
```

`make integration` includes these scenarios. Test bootstrap rejects any database
outside literal loopback or with a name other than `supivpn_test`.
Live acceptance after deployment covers client traffic and source IPs, rolling
updates, routes/ACLs, and termination of access according to the agreed contract.
