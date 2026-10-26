# Profile ownership and a two-port migration

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

**Available since v0.8.0 (schema 11).** The v0.8.1 owner-label fix requires
schema 12. OpenVPN itself remains unmodified; existing bound profiles keep
working without reissue. See [upgrade steps](POSTGRES.md#schema-11-to-12-v081).

## What is bound

A profile contains a random opaque ID and a separate 256-bit secret in an inline
`auth-user-pass` block. Neither the SAML username nor an IdP password appears in
that block. Issuance follows a verified, group-authorized SAML login. PostgreSQL
stores the proof's SHA-256 digest, the verified subject hash (issuer and NameID),
and `active`/`blocked` state. Schema 12 also stores `owner_username`, the verified
SAML NameID, for privileged operator inspection. This audit label is never used
as authorization evidence or embedded in a client profile. The database never
stores the plaintext proof.

The OpenVPN management `CONNECT` environment delivers that proof on the exact
CID/KID. The agent registers it with its authenticated controller identity. A
fresh SAML login must match the recorded owner and current group policy before
VPN admission. A supplied Device ID, username label, IP address or timing match
cannot substitute for this check. Rekey must retain the same proof.

Profiles are reusable. There is one registry entry per issued profile, not per
VPN reconnection. Existing login/replay cleanup remains separate. Keep registry
entries while their profiles can still be used; do not recycle profile IDs.
Changing the IdP issuer or NameID requires issuing new profiles.

Possession of both a copied profile and its owner's SAML session still grants
access. This binds a profile to an account, not to a physical device. Keep browser
login confirmation enabled unless accepting its documented relay risk. Blocking
a profile stops new admission and incomplete admission checked by the controller;
it does not continuously revoke an already admitted tunnel. Use the existing
operator session-disconnect action for immediate termination.

## Two distinct listeners

The compatibility option is explicit on **each agent**:

- `"profile_binding": "legacy"` (also the transitional default when omitted):
  existing SAML authorization without an owner-bound profile proof.
- `"profile_binding": "required"`: a proof and its active verified owner are
  required. A separate PostgreSQL-backed controller is mandatory; the embedded
  controller does not implement the registry.

Run two unmodified OpenVPN processes, each with its own agent, management socket,
node identity and nonoverlapping VPN subnet. For example:

| Listener | UDP port | Node ID (VM example) | Device | VPN subnet |
| --- | --- | --- | --- | --- |
| Existing profiles | 1194 | `vm-legacy` | `supivpn0` | `10.203.0.0/24` |
| Bound profiles | 1195 | `vm-bound` | `supivpn1` | `10.204.0.0/24` |

Choose subnets that do not overlap your existing networks. Keep group priorities,
identity rules and the shared connection limit consistent, but assign each
agent pools inside its own subnet. Configure forwarding, firewall, return routes
and DNS for both. There is no tunnel migration between processes; reconnecting
requires a new SAML login and obtains a different VPN IP.

**Install the legacy format gate on every old listener before issuing any bound
profile.** Port numbers alone are not protection: users can edit `remote`.
The authenticated tls-crypt-v2 metadata distinguishes old timestamp keys from
new versioned profile keys. The two gates accept disjoint formats:

```text
# Old listener (retain its other existing directives):
script-security 2
tls-crypt-v2-verify "/usr/sbin/supivpn -verify-profile-metadata legacy"

# New listener (retain certificate validation, management auth and other settings):
port 1195
dev supivpn1
server 10.204.0.0 255.255.255.0 nopool
management /run/supivpn-bound/management.sock unix
script-security 2
tls-crypt-v2-verify "/usr/sbin/supivpn -verify-profile-metadata required"
```

These are fragments, not complete server configurations. Do not append duplicate
`server`, `management`, `port` or `dev` options to an existing file. The helper
reads only OpenVPN's authenticated `metadata_type` and `metadata_file`. Unknown
formats, missing metadata and timestamps more than five minutes in the future
fail closed. To enforce an age
limit, add `-profile-max-age 2160h` to either command; zero defaults to no age limit.
Use the same wrapping key when intended by your deployment. Never put the
wrapping key or profile secret in command arguments, logs or support tickets.

A new profile presented to the old listener is rejected before SAML, even if its
inline proof was removed. An old profile on the new listener is also rejected.
Do not offer legacy fallback on the same port, on proof failure, or for a blocked
profile. An operator retaining the legacy listener accepts the legacy login risk
for users who still possess legacy profiles. Disable that listener to enforce
ownership everywhere; blocking a new profile cannot revoke an old format key.

## VM and systemd configuration

1. Back up the database, run the normal explicit migration to schema 12, and
   upgrade all controllers and agents together. Reapply restricted runtime grants
   for separate roles. Old binaries are not promised to accept the new schema;
   the compatibility window is for client profiles, not arbitrary binary/schema
   skew. Test restore procedures before deployment.
2. Add the legacy metadata gate above to the existing OpenVPN configuration and
   restart that pair during a maintenance window. Verify an existing profile can
   still connect before enabling new issuance.
3. Put the second pair's reviewed configuration under
   `/etc/supivpn/nodes/bound/agent.json` and `openvpn.conf`. Use the installed
   `supivpn-node@bound.service` and `supivpn-openvpn@bound.service` templates.
   They retain the same hardening and lifecycle dependency as the existing units.
   The node unit creates `/run/supivpn-bound` and `/var/lib/supivpn-node-bound`.
   Set the second agent's `profile_binding` to `required`, `management_socket`
   to `/run/supivpn-bound/management.sock`, and all generation/state paths under
   its own state directory. Give its HTTPS health listener a distinct loopback
   address/port, for example `listen: 127.0.0.1:9444` and
   `public_url: https://vpn.example.test:9444`; retain the common browser-login
   URL in `remote_controller.public_url`. Keep its `vpn_network` and every group
   pool inside `10.204.0.0/24`. Preserve the remaining validated agent settings.
4. In the controller's `vm` block, retain the existing socket/UID/node and add:

   ```json
   "additional_agents": [
     {"socket": "/run/supivpn-controller/agent-bound.sock", "uid": 0, "node_id": "vm-bound"}
   ]
   ```

   Use your existing controller-owned 0700 runtime directory. The new agent's
   remote controller configuration must point to this socket and `vm-bound`.
   Its UID must match the trusted local agent process. The second socket cannot
   reuse the first socket or node identity. No agent API is added to public HTTPS.
5. Set the public controller's `profile` block:

   ```json
   {
     "endpoint": "vpn.example.test",
     "template_file": "/etc/supivpn/controller/client.ovpn.example",
     "server_key_file": "/etc/supivpn/keys/tls-crypt-v2-server.key",
     "binding": "required",
     "port": 1195,
     "server_url": true
   }
   ```

   Keep existing absolute template/key paths if different. Lambda keeps its
   existing deferred wrapping-key loader and must omit `server_key_file`.
   Bound downloads include `verify-x509-name vpn.example.test name`: provision a
   VPN server certificate with that **exact common name**, plus the valid trusted
   chain and TLS-server purpose. This is OpenVPN's exact CN comparison, not a
   wildcard/SAN hostname matcher. Test certificate renewal before rotating it.
   Bound profiles also enable `push-peer-info` for client diagnostics. Do not add
   `auth-nocache` or replace their inline credential block: rekey needs the proof.
6. Restart the controller, start `supivpn-node@bound`, and enable that unit only
   after the checks below pass. The node unit brings up its OpenVPN instance.
   The package does not automatically restart working services during upgrade.

The existing setup helper creates the minimal single-listener deployment. It
**does not perform this two-port conversion automatically**. Use the explicit
configuration above; do not rerun setup to overwrite a working deployment.

For Lambda/EC2, use distinct old/new node instances and trusted IAM identities,
with separate port/target-group routing and nonoverlapping pools. The existing
fencing identity is an EC2 instance ID. Two agents on one EC2 instance sharing a
single IAM identity are not a supported substitute for two node identities.

## Server URL and Linux import

**Recommended for OpenVPN Connect:** Server URL import. With
`profile.server_url=true`, OpenVPN Connect can discover
`<public_url>/openvpn-api/profile` through GET or HEAD. The response advertises
`Ovpn-WebAuth: SupiVPN,external`. The browser follows a fresh SP-initiated SAML
flow; successful authorization displays an explicit **Open in OpenVPN Connect**
link. The profile is created only when Connect redeems its one-use HTTPS grant.
The grant expires in 60 seconds, is stored only as a hash across replicas, and
cannot be replayed. A failed download needs another login. No IdP password or
browser cookie is handed to Connect.

Expose these exact public routes on proxies/API Gateway, with the same optional
`/supivpn` prefix as other controller routes:

| Method | Path |
| --- | --- |
| GET, HEAD | `/openvpn-api/profile` |
| GET | `/profile/connect` |
| GET | `/profile/import/{token}` |

Preserve response headers and existing SAML cookies/body handling. Disable cache
for all authentication/profile paths. **Redact the import token path and SAML
query/body values in proxy, WAF, analytics and access logs.** No third-party
resources are loaded on the handoff page. Do not share screenshots of its link.
For a prefixed public URL, enter that full base URL in Connect and verify that
that client version discovers the prefixed route; do not expose a catch-all API.

Linux uses the existing browser `/profile` download after SAML, followed by local
`.ovpn` import. OpenVPN 3 Linux's native Access Server importer does not implement
this Server URL/SAML flow. No separate SupiVPN import helper is required.

The automated compatibility fixture uses unmodified OpenVPN 2.7.8 and OpenVPN 3
Linux 27.1: file import, browser challenge, delayed signed SAML, tunnel traffic,
proof transport and cross-port format rejection. Connect 3.9.0 on macOS accepted
the generated bound file through its CLI importer. On 2026-10-24, Connect 3.9.0
(6050) on macOS arm64 also passed native Server URL import: discovery, browser
handoff, signed synthetic SAML, the one-use HTTPS grant and successful UI import.
The operator completed the browser steps and confirmed the imported profile;
the fixture independently verified persistence as an active bound profile.
See [the repeatable fixture](CONNECT_TEST.md#server-url-import). This check used
a trusted test HTTPS certificate; certificate validation remained enabled.
Native Connect tunnels, other desktop/mobile platforms, a prefixed Server URL,
and this new flow with a real IdP remain separate acceptance checks.

Sources: [OpenVPN web authentication/profile protocol](https://github.com/OpenVPN/openvpn-rfc/blob/master/webauth.md),
[Connect profile import](https://openvpn.net/connect-docs/import-profile/),
[OpenVPN 3 Linux import](https://openvpn.net/as-docs/v3/tutorials/tutorial--openvpn3-as-import-connection-profile/).

## Inspect, block and reactivate

On a combined Debian host, prefer the new [local supivpn-cli](CLI.md), included
in the metapackage since v0.8.0. For Lambda, see the temporary
[bounded SQL procedure and limitations](LAMBDA_PROFILE_ADMIN.md). Neither method
turns a profile block into immediate tunnel termination or an account-wide ban.

Use a privileged operator transport, never the browser or agent API. The recovery
Lambda accepts these envelopes through its existing restricted invocation path.
On a VM, `supivpn-controller -config <controller.json> -operator-request` accepts
the same JSON on stdin using `SUPIVPN_DATABASE_URL` and configured database TLS.
Supply that credential through your existing secret-loading mechanism; do not
paste its value into a shell command. The VM command starts no listeners.

```json
{"source":"supivpn.operator.v1","action":"profile-status","profile_id":"svp1_0123456789abcdef0123456789abcdef"}
```

Use the returned revision when mutating:

```json
{"source":"supivpn.operator.v1","action":"profile-block","profile_id":"svp1_0123456789abcdef0123456789abcdef","expected_revision":1}
```

`profile-activate` uses the same shape with the latest revision. A stale revision
fails; after an ambiguous response read status before deciding whether to retry.
Responses contain ID, state, revision, creation time and, from v0.8.1,
`owner_username`; never the proof, digest or SAML owner hash. Empty labels mean
the old label has not been recovered yet. With separate component database roles, the public runtime
can issue profiles and fill owner labels but cannot change their state; agents can check proofs
without selecting the registry. The recovery role can update only
state/revision, not ownership or proof digests. The combined VM controller uses
its existing shared runtime role and table privileges; the operator entry point
must remain restricted to trusted administrators.

## Device diagnostics

`vpn.tunnel_established` records `profile_id` for a bound session and, when
provided, `client_device_id` plus `client_device_id_source` (`UV_UUID` or
`IV_HWADDR`). This supports grouping connections by profile to spot several
claimed devices. Legacy sessions have no profile ID. Connect/Linux versions may
omit identifiers; missing, malformed or duplicate labels are omitted. No access
is refused solely because a Device ID is absent. Keep log access and retention
appropriate for pseudonymous device/user activity.

These values are client claims, can be cloned or changed, and are not attestation.
Device enforcement is not implemented. Future enforcement must account for
reinstalls, lost devices, rotation and administrative recovery.

## Acceptance and compatibility window

Before enabling issuance, verify:

1. A fresh SAML profile download contains an opaque proof and the new port; it
   connects as its owner and is rejected after login as a different user.
2. A blocked profile, wrong/missing proof, and a new profile edited to the old
   port are denied. An old profile still works only on the legacy port.
3. Reconnect and rekey preserve the binding; shared per-user connection limits
   apply across both listeners. Test interrupted browser login as well.
4. Connect imports a one-use link; retries/expiry require a new SAML login.
   Linux file import establishes a tunnel and completes delayed SAML login.
5. Journald contains the verified username, opaque profile ID and available
   device label, but no proof, SAML assertion or import token.
6. Exercise block/reactivate with stale revisions and the least-privileged roles.

The first minor release shipping this feature is **M**. Legacy profile support
remains available during **M and M+1**; default enforcement/removal is planned
no earlier than **M+2**, after explicit release notes and migration guidance.
Operators can enforce sooner by disabling their legacy listener. There is no
calendar-triggered port shutdown. Only a critical vulnerability may require an
earlier breaking security change, documented in its advisory and upgrade notes.
