# SupiVPN client profile download

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Direct download entry: **`<public_url>/profile`**.
For `public_url=https://login.example.test/supivpn`, this is
`https://login.example.test/supivpn/profile`. Deployment defines the address.
One Okta SAML App can provide both VPN authentication and the dashboard tile;
a separate Bookmark App is optional.

See the [profile ownership and two-port migration guide](PROFILE_BINDING.md) for the account-bound profile format available from **v0.8.0**,
active/blocked controls, Server URL import and Linux file-import support.

## One Okta SAML App

Configure the existing SAML application after deploying the controller and route:

| Okta setting | Value |
| --- | --- |
| Single sign-on URL (default IdP-initiated POST target) | `<public_url>/saml/launch` |
| Other Requestable SSO URLs | `<public_url>/saml/acs`, index `1` |
| Audience URI (SP Entity ID) | Existing `<public_url>/saml/metadata` |
| Default RelayState | Leave empty |
| App visibility | Show the SAML application's tile to users |

Keep the existing signing settings, NameID, groups claim, assignments, and
authentication policy. SupiVPN explicitly requests `/saml/acs` in every
AuthnRequest. The authenticated response's Destination and bearer Recipient
must both match that ACS, not `/saml/launch`. Check any explicit Okta
Recipient/Destination overrides if the callback is rejected; do not relax
controller validation. The published SP metadata continues to advertise only
the real ACS. The launch URL is configured separately in Okta.

This setup uses Okta's static **Other Requestable SSO URLs**. Do not enable
**Signed Requests** for this setup: current SupiVPN AuthnRequests are unsigned,
and Okta switches from static ACS URLs to signed-request configuration when
that option is enabled. Response/assertion signature verification stays mandatory.
See [Okta's SAML field reference](https://help.okta.com/oie/en-us/content/topics/apps/aiw-saml-reference.htm).

The launch handler is navigation, not an authentication callback. It discards
the initial POST body without parsing XML or trusting any claims, cookies, or
RelayState, then returns `303` to the fixed local `/profile` path. It creates no
pending login, reads no key, and makes no database call. Only POST is accepted;
queries and bodies over 1 MiB are rejected, including unknown-length bodies.
The normal HTTPS origin checks and no-store headers apply.

A fresh SP-initiated login then binds the response to the browser. The extra
Okta round trip will usually reuse the active IdP session; password/MFA prompts
remain subject to the application's policy. Unsolicited assertions can never
directly authorize a profile or a VPN tunnel.

## Login and issuance

1. The user clicks the SupiVPN SAML tile. Okta POSTs to `/supivpn/saml/launch`,
   which redirects to `/supivpn/profile`. A direct link or an existing Bookmark
   can also open `/supivpn/profile`.
2. GET `/supivpn/profile` creates a one-time PostgreSQL request, browser cookie,
   and SP-initiated AuthnRequest. No key is read at this stage.
3. Okta returns an assertion to the existing `/supivpn/saml/acs`. The controller
   verifies the signature, InResponseTo, audience, validity periods, cookie,
   and exact VPN groups according to priority.
4. After atomically consuming the request, the controller reads the shared wrapping
   key and generates a new tls-crypt-v2 client key. The browser receives
   a `supivpn.ovpn` attachment.
5. Import the profile into OpenVPN Connect. Every VPN connection performs SAML
   independently; neither group nor IP is fixed in the profile.

App assignment and at least one permitted VPN group are required. Acceptance
of IdP-initiated assertions remains disabled; profile and VPN authorization
use the same SAML app and strictly correlated ACS.

Different controller replicas can handle GET and ACS.
`supivpn.profile_logins` is separate from node-bound logins; assertion replay
protection is shared. Concurrent callbacks issue at most one profile.
A lost download or key-store failure requires reopening the tile or direct link,
not repeating the authenticated ACS POST.

## Deployment

1. Build the agent, profile CLI, migrator, and required controller:
   [runtime](RUNTIME.md#manual-checks-and-builds).
2. Prepare the database and apply migrations, including `002_profiles.sql`,
   before starting the controller. Tables are owned by `supivpn_owner`;
   runtime receives DML. Controller startup performs no DDL.
3. Enable profile configuration; supply the template and access to the same
   wrapping key used by the nodes.
4. Allow GET `<public_url>/profile`, POST `<public_url>/saml/launch`, and POST
   `<public_url>/saml/acs` through the HTTPS proxy/API. Create an exact launch
   method/resource in API Gateway, include it in the deployed stage and Lambda
   invocation permissions, and update reverse-proxy path allowlists. Do not use
   a catch-all route. Preserve rate limits, cache bypass, body-size limits,
   and browser/agent route separation. VM deployments expose the same handler.
5. Configure the SAML tile as above. Check a complete tile download and a VPN
   login before removing the old Bookmark. A direct `/profile` link remains valid.

No database migration or node/profile regeneration is required for tile support.
Existing VPN logins continue to request the same ACS. Before rolling back to a
controller without `/saml/launch`, restore Okta's default SSO URL to `/saml/acs`
and use the direct link or Bookmark again. Leaving the default launch URL on an
old controller will break tile downloads. If the second response goes back to
`/saml/launch`, correct the requestable ACS configuration instead of permitting
unsolicited authentication or repeatedly following the resulting redirects.

The profile is returned directly from ACS POST. There is no open key-bearing
GET endpoint or long-lived download token.
Headers: `Cache-Control: no-store, private`, `Content-Disposition: attachment`,
`Content-Type: application/x-openvpn-profile`.
Keep API body tracing disabled. Never log SAML or profile bodies.

## VM mode and AWS independence

`internal/profile.DownloadIssuer` contains no AWS SDK and accepts a key loader
function. The Lambda adapter reads the ARN from `SUPIVPN_TLS_CRYPT_V2_SECRET_ARN`;
IAM grants only GetSecretValue for one wrapping key, without Put/Create/rotation.

Optional VM JSON section:

```json
"profile": {
  "endpoint": "vpn.example.test",
  "template_file": "/etc/supivpn/client.ovpn.template",
  "server_key_file": "/var/lib/supivpn/tls-crypt-v2-server.key"
}
```

Use `examples/client.ovpn.example` as the template: it contains a placeholder
remote and tls-crypt-v2 slot; the controller fills in the endpoint.
Provisioning delivers the key file with mode 0600. The VM controller UID must
be able to read it without broadening file permissions.
Without `profile`, both download entry and launch return 404. The Lambda ZIP contains the executable
and template, optionally public metadata, but no private keys.

Key format: 256 random client-key bytes plus a wrapped copy with timestamp metadata;
standard Go AES-256-CTR/HMAC-SHA256.
Format reference:
[OpenVPN 2.7.8 tls-crypt-v2](https://github.com/OpenVPN/openvpn/blob/v2.7.8/src/openvpn/tls_crypt.c).
Native integration tests verify OpenVPN acceptance, not just agreement with another
Go implementation.

## Operator checks

Run from the repository root:

```bash
go test -race -count=1 -timeout=180s ./...
go vet ./...
```

SQL/SAML tests use only disposable local PostgreSQL 18 as described in
[POSTGRES.md](POSTGRES.md):
`TestProfileDownloadPostgresSAML` and `TestProfileMigrationUpgradeAndExpiry`.
The profile flow test covers tile and direct entry, a fresh browser-bound
request across replicas, signature/request/recipient/destination failures,
group denial, replay, concurrent callbacks, and key-store failures.
Unit tests cover the navigation-only launch boundary and exact REST/HTTP v2 routes.
For OpenVPN acceptance of Go-generated keys, rebuild the native suite using
[these instructions](../testdata/openvpn/README.md) and run `TestOpenVPN`.

After deployment:

- The SAML tile and direct link return a complete profile; reissuance generates a different client key.
- The new profile works on all nodes with an IP from the correct group/node pool.
- Assignment without a VPN group returns 403 without a file; no assignment is rejected by the IdP.
- A repeated callback issues no file; database/key-store failure cannot bypass SAML.
- Verify tile/direct entry and ACS availability during an active full tunnel:
  client DNS must not shadow the controller's public hostname.
  Configure selective forwarding when private wildcards exist.
  See [setup and checks](HOST.md#client-dns-through-the-local-node).

Individual client-key revocation and binding profiles to specific devices are
not implemented. Profiles admit clients to TLS/SAML; they do not identify users.
[TLS_CRYPT_V2.md](TLS_CRYPT_V2.md) describes the current TLS hostname verification limitation.
