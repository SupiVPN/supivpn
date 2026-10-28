# Profile ownership and enforcement

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

## Required ownership in v0.9.0

**Unreleased change:** v0.9.0 requires bound profiles on every supported listener.
The `legacy` agent mode and legacy metadata gate are removed. Omitting
`profile_binding` now selects `required`; explicitly setting `legacy` fails
startup. The public controller likewise defaults `profile.binding` to `required`
and rejects `legacy`. All production agents use a separate PostgreSQL-backed
controller; the old embedded controller is no longer a supported deployment.

This intentionally shortens the previously announced transition: v0.8.x remains
the last compatible series for unbound profiles, instead of the previously
planned v0.9.x. Operators must migrate those users **before upgrading to v0.9.0**.
This is an explicit release scope change, not a claim of a newly classified
Critical vulnerability. Do not expose an old listener alongside a new deployment
and describe the whole deployment as ownership-enforced.

**Bound UDP-only profiles issued by v0.8.x remain valid.** They do not need new
secrets or tls-crypt-v2 keys. Keep their UDP endpoint/port and trust material.
A profile without the opaque inline proof must be downloaded again after its
owner signs in through SAML; adding an arbitrary username is not a migration.
Unknown metadata, stripped or wrong proofs, blocked profiles, owner mismatches
and infrastructure errors never trigger a less restrictive path.

## VM and systemd configuration

1. Back up the database and use schema 12. A deployment already on v0.8.1 or
   later needs no schema change for v0.9.0. Keep the restricted runtime grants.
   Upgrade the controller and agent together in a maintenance window; mixed
   v0.8/v0.9 server components are not a supported rolling-upgrade combination.
2. While still on v0.8.x, issue bound profiles to every user. Verify owner match,
   blocked-profile refusal and reconnect. Preserve the existing bound listener's
   UDP port when consolidating to one agent; do not silently move old bound
   profiles to another port. Stop and disable the former unbound listener.
3. Configure one node with `profile_binding: "required"`, its existing private
   management socket, node identity, state directory and group pools. Use the
   required gate in every OpenVPN server configuration:

   ```text
   script-security 2
   tls-crypt-v2-verify "/usr/sbin/supivpn -verify-profile-metadata required"
   ```

   The helper checks authenticated tls-crypt-v2 metadata, format and timestamp.
   Unknown/missing metadata and timestamps over five minutes in the future fail
   closed. Optionally add `-profile-max-age 2160h`; the default has no age limit.
4. Configure the controller's `profile` block using the actual existing paths
   and bound UDP port (1194 is the new-install default):

   ```json
   {
     "endpoint": "vpn.example.test",
     "template_file": "/etc/supivpn/controller/client.ovpn.example",
     "server_key_file": "/etc/supivpn/keys/tls-crypt-v2-server.key",
     "binding": "required",
     "port": 1194,
     "server_url": true
   }
   ```

   Lambda retains its deferred wrapping-key loader and omits `server_key_file`.
   Every bound profile verifies the exact certificate common name against
   `endpoint`. Provision the VPN server certificate with that exact CN and a
   valid trusted chain; this is not DNS SAN or wildcard matching. Retain the
   inline credential block and do not add `auth-nocache`: rekey needs the proof.
5. Start the controller and node, check readiness, and repeat the acceptance
   checks below. Packages do not automatically restart working services.

The v0.9.0 setup helper creates a bound UDP-only deployment by default. Optional
TCP fallback uses a second unchanged OpenVPN process controlled by the **same
agent and node**, with the same address pools and security checks. See
[UDP and optional TCP fallback](TRANSPORTS.md) for configuration and host routing.
The two transports are unrelated to the removed legacy/new-profile migration.

For Lambda/EC2, upgrade both controller Lambdas and the agent on each VPN host;
a Lambda update alone cannot enforce the host's metadata gate or create TCP.
Keep the existing trusted IAM/node identity and wrapping key. The same one-agent
transport arrangement applies; no additional EC2 identity is needed for TCP.

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
claimed devices. Connect/Linux versions may
omit identifiers; missing, malformed or duplicate labels are omitted. No access
is refused solely because a Device ID is absent. Keep log access and retention
appropriate for pseudonymous device/user activity.

These values are client claims, can be cloned or changed, and are not attestation.
Device enforcement is not implemented. Future enforcement must account for
reinstalls, lost devices, rotation and administrative recovery.

## Acceptance before upgrading

1. A SAML-authorized download contains an opaque proof, connects as its owner
   and is rejected after login as a different user.
2. Unbound, stripped, unknown and blocked profiles fail on every enabled
   transport. Wrong proof or controller/database failure never opens access.
3. Existing bound UDP-only profiles reconnect and rekey. New dual-transport
   profiles prefer UDP and can authenticate over TCP when UDP is unavailable.
   Per-user limits apply across both transports and nodes.
4. Connect imports a one-use link; retries/expiry require a new SAML login.
   Linux file import establishes a tunnel and completes delayed SAML login.
5. Journald contains the verified username, opaque profile ID and available
   device label, but no proof, SAML assertion or import token.
6. Exercise block/reactivate with stale revisions and least-privileged roles.

Do not down-migrate the database or restore stale authorization state as a
rollback shortcut. Preserve configuration backups and test an explicit rollback
of the complete server pair; re-enabling an old legacy listener restores its old
risk and is not ownership-enforced operation.
