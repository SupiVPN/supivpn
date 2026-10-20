# SAML groups and IP pools

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The controller obtains membership only from a verified SAML assertion.
Standard SAML IdPs are supported; Okta configuration is shown below.
SupiVPN does not depend on SCIM or a group lookup API.

## Okta app setup

Create a custom SAML 2.0 app and choose the controller's HTTPS `public_url`,
for example `https://login.example.test/supivpn`.

| Field | Example value |
| --- | --- |
| Single sign-on URL / ACS | `https://login.example.test/supivpn/saml/acs` |
| Recipient / Destination | The same ACS URL |
| Audience URI / SP Entity ID | `https://login.example.test/supivpn/saml/metadata` |
| Name ID format | Unspecified |
| Application username format | For example, Okta username prefix |
| Default RelayState | Empty |
| Response / Assertion Signature | Signed / Signed |
| Signature / Digest Algorithm | RSA-SHA256 / SHA256 |
| Assertion Encryption | Unencrypted |
| Signed Requests / Single Logout | Disabled in this example |

NameID does not have to be an email address; signed group membership determines
the pool. Assign the app to the required users/groups and agree on IdP policy
with the operator. The current controller does not request `ForceAuthn=true`;
an existing browser session may complete SAML without another password prompt.

The OpenVPN client initiates VPN login. Profile downloads can use the same
[SAML app tile](PROFILES.md): the launch endpoint discards its unsolicited
POST and redirects to a fresh SP-initiated flow. Direct links and Bookmarks also
work. An IdP-initiated assertion never replaces the correlated authorization response.

## Groups claim

Example **Group attribute statements** for `operations-vpn` and `engineering-vpn`:

| Field | Value |
| --- | --- |
| Name | `groups` |
| Name format | Unspecified |
| Filter | Matches regex |
| Value | `.*-vpn$` |

This naming convention is illustrative; choose a filter matching your own names.
Runtime `saml_groups_attribute` must match the claim name.
Expected NameFormat is `urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified`;
an omitted NameFormat is accepted too.
Each group must be a separate `AttributeValue`, not a CSV or JSON string.

Names match exactly and case-sensitively; group IDs are unnecessary.
Supported names contain 1-128 ASCII letters, digits, dots, underscores, or hyphens,
starting with a letter or digit.
Configure `groups[].name/priority` in the controller and
`group_pools[].group_name/priority/cidrs` in agents. Policies must agree.

A missing, empty, or repeated claim, invalid name, or lack of a permitted group
causes rejection. Unknown names grant no access; repeated values are deduplicated.
Renaming a group requires updating configuration.

The operator stores public IdP metadata in deployment configuration.
Deployment supplies it at `idp_metadata`; this file is not part of product source.

## Pools

Lower priority numbers win. A user receives one group; permissions from multiple
groups are not combined. The agent tries that group's local `cidrs` in order,
then rejects when all are full, without falling back to another group.

The legacy `cidr` field supports one pool and cannot be combined with `cidrs`.
For multiple nodes, partition pools into disjoint parts in advance:
[algorithm and routing](HA.md#node-count-and-group-expansion).

OpenVPN uses `server ... nopool`; the agent assigns IPs through `ifconfig-push`.
Leases belong to CIDs and are released after DISCONNECT. REAUTH retains the IP
and original deadline. `learn-address` allows only the assigned IPv4 address.

## Live checks

| Scenario | Expected result |
| --- | --- |
| One permitted group | IP from its local pool |
| Multiple permitted groups | Group with the lowest priority number |
| App assigned, no VPN groups | SupiVPN rejection |
| App not assigned | IdP rejection |
| Group with multiple CIDRs | Continue in the next pool when the first fills |
| All group pools full | Rejection without changing groups |

Measure group-change propagation with your IdP's existing browser session.
Membership changes alone do not close established tunnels; the next SAML flow
obtains a new decision.
Also test simultaneous devices, session expiry, and node failure.

For deployments using `supivpn.service`:

```bash
sudo journalctl -u supivpn.service --since '5 minutes ago' --no-pager
```

Diagnostic entries contain CID, group_name, and IP; never enable full assertion logging.
Rejection categories: `invalid_groups_claim`, `no_vpn_group`, and `pool_full`.

References:
[custom SAML app](https://developer.okta.com/docs/guides/create-an-app-integration/saml2/main/),
[app fields](https://help.okta.com/en-us/content/topics/apps/aiw-saml-reference.htm),
[group statements](https://help.okta.com/en-us/Content/Topics/Apps/define-group-attribute-statements.htm).
