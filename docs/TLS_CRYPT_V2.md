# SupiVPN — tls-crypt-v2

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Flow: **tls-crypt-v2 → TLS without client certificate → SAML → group/IP**.
OpenVPN Community **2.7.8** handles tunnels. Bootstrap and CLI issuance use its
native `--genkey tls-crypt-v2-server/client`.
For [HTTPS issuance](PROFILES.md), the controller generates client keys in memory
using Go `crypto/rand`, AES-256-CTR, and HMAC-SHA256, in tls-crypt-v2 format with
timestamp metadata. Lambda does not need an OpenVPN binary.
Native integration checks interoperability; Go-generator cases passed with
OpenVPN 2.7.7 on September 21, 2026.

## Keys and access boundaries

| Material | Storage | Purpose |
| --- | --- | --- |
| One server wrapping key per cluster | Protected deployment storage; local copy on every node | Unwraps keys sent by clients |
| Fresh client key per issuance | Inline `<tls-crypt-v2>` in the .ovpn profile | Permits the TLS/SAML handshake |
| TLS server certificate/key | Operator's secure certificate/key/chain delivery | Server TLS; independent lifecycle |

The server wrapping key is never included in profiles. There is no client PKI,
`tls-auth`/`tls-crypt` fallback, or VPN access based on profile possession alone:
SAML must authorize the user and VPN group.

Without the correct client key, VPN connections never reach WEB_AUTH.
This does not conceal public SAML HTTPS endpoints or replace their protection.
`force-cookie` is not currently enabled; verify OpenVPN Connect compatibility
separately in the chosen deployment.
[OpenVPN semantics](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html).

## AWS independence

- `internal/profile`: OpenVPN, profile format, private files, and
  `SecretStore.Get/CreateIfAbsent`. This package has no AWS SDK dependency.
- `internal/awsruntime/tlscrypt.go`: Secrets Manager adapter.
  CLI `supivpn-profile -init -secret-arn ARN` enables it; region comes from the
  ARN and EC2 credentials from the instance role.
- `supivpn-profile -init` without ARN creates or validates a local key.
  This supports local environments; never run it independently on two empty
  cluster nodes.
- `supivpn-profile -out FILE` reads the installed local key without contacting AWS.
  Keys never enter process arguments, stdout, or error messages.

Other clouds may provision the same private file or implement another adapter.
`CreateIfAbsent` must atomically choose one value and return it to all concurrent
callers. The CLI currently links the AWS adapter, but profile issuance logic and
local mode do not require it.

## Cluster bootstrap

Every node and the issuance service must use the same wrapping key.
Deliver it through secure provisioning or the AWS adapter.
The AWS contract below leaves secret name, account, region, and IAM to the operator.

1. Deployment creates only the secret container and IAM Get/Put for its exact ARN.
   The value never enters Terraform state, outputs, provisioner content, or Lambda ZIP.
   The controller receives only GetSecretValue for authorized HTTPS issuance;
   it cannot create or rotate the key.
2. EC2 reads AWSCURRENT. If present, the tool validates it and installs it locally
   atomically. Any existing local key must match.
3. For an empty secret, the tool proposes an existing valid local key or generates
   a fresh one. The adapter uses one fixed shared initial-version
   `ClientRequestToken`. Different values cannot replace one another in that
   version; after write/conflict, both processes read the stored result.
4. Only the confirmed key is installed at
   `/var/lib/supivpn/tls-crypt-v2-server.key`: file 0600, directory 0700.
   Timeout, IAM denial, corruption, or key mismatch stops provisioning.
   There is no fallback to an independently generated local key.

This relies on immutable versions sharing one token in
[AWS PutSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html).
The initial version ID is part of the contract and must not change between releases.
Concurrent external rotation during bootstrap is unsupported.

All AWS cluster nodes receive the same ARN. Outside AWS, provision the same key
file to every node. Sharing a key does not migrate sessions/IPs: node failure
requires new SAML login and IP, interrupting TCP sessions.
[Cluster and failover verification](HA.md).

## Lifecycle

- Restart, repeated apply, and TLS certificate updates do not change the wrapping
  key. Startup reads the local file; missing files/unsafe permissions stop startup.
- Replacement EC2 retrieves the retained secret; profiles need not be reissued.
- Infrastructure removal must not silently destroy the only wrapping-key copy if
  issued profiles must survive. Deployment defines retention, backup, recovery,
  and secret ownership. A new value requires new profiles.
- Automatic rotation accepting old/new keys simultaneously and individual profile
  revocation are not implemented. SAML-authorized HTTPS issuance: [PROFILES](PROFILES.md).
- AWS IAM/KMS permissions must allow the specific secret; custom KMS keys or
  cross-account access need appropriate deployment policies.

## Issuance and verification

Deployment installs `supivpn-profile` and `client.ovpn.template`.
Set your VPN endpoint in the template. Using standard CLI paths:

For v0.9.0, obtain a profile through the controller's SAML-authorized
[download or Connect import](PROFILES.md). The retained `supivpn-profile -out`
utility generates only a historical unbound format; it cannot verify a SAML
owner and its output is refused by v0.9.0 listeners. Do not use it to provision
current users. The `-init` wrapping-key bootstrap remains supported.

Bound downloads check CA, certificate validity and the exact server CN.
No explicit KU/EKU directives are included for client compatibility.
TLS-crypt-v2 does not replace server identity verification. The planned
[DNS SAN verification](#planned-dns-san-verification) remains a separate limitation.

Locally from the repository root:

```bash
go test -race -count=1 -timeout=120s ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn ./cmd/supivpn
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-profile ./cmd/supivpn-profile
```

Unit tests cover concurrent bootstrap across nodes and for one file, replacement
node recovery, migration of a local key, conflicts, storage failures, and preventing
issuance with unconfirmed keys. The AWS adapter uses a fake API with immutable
versions; this is not a live AWS test.

[Native OpenVPN integration](../testdata/openvpn/README.md) checks actual
generation, missing/foreign-key rejection before WEB_AUTH, and SAML/group flow.
Without `SUPIVPN_TEST_OPENVPN`, regular Go tests skip this integration test.

In your deployment, verify issued-profile login, missing-key denial, and group
pools. After controlled node replacement, log in with a **previously issued**
profile. Local tests do not replace IdP, client UI, and load-balancer verification.

## Planned DNS SAN verification

Decision date: **2026-10-05**. Use a public CA and verify the expected VPN DNS
name against the server leaf certificate's `subjectAltName` `dNSName` entries,
in addition to chain, validity, and server-purpose verification. Do not fall back
to CN, substitute a private CA, or silently replace this with leaf fingerprint
pinning. The expected name must come from trusted profile configuration, never
from the peer certificate or a server-pushed option. DNS resolution to an IP
address must not change the expected identity.

**Status: blocked on VPN client support; not implemented or validated in
OpenVPN Connect.** OpenVPN Connect remains a required client. Keep this issue
open until a supported Connect release implements the required verification;
switching clients or building a custom client is outside the selected scope.
Checking certificates during issuance or on the server cannot replace
verification inside the client's actual VPN TLS handshake.

Upstream source and documentation reviewed on the decision date:

- OpenVPN 3's [VerifyX509Name](https://github.com/OpenVPN/openvpn3/blob/master/openvpn/ssl/verify_x509_name.hpp)
  supports Subject DN, CN, and CN-prefix matching, not DNS SAN matching.
- The VPN [protocol stack](https://github.com/OpenVPN/openvpn3/blob/master/openvpn/ssl/protostack.hpp)
  calls the TLS factory without a hostname. The separate hostname-taking overload
  in the [OpenSSL wrapper](https://github.com/OpenVPN/openvpn3/blob/master/openvpn/openssl/ssl/sslctx.hpp)
  therefore does not establish DNS SAN verification for a VPN profile. Setting
  SNI alone is not certificate hostname verification.
- The official [Connect directive matrix](https://support.openvpn.com/hc/en-us/article_attachments/17545051570587)
  lists `tls-verify` and `tls-export-cert` as ignored because scripts/plugins are
  unsupported. Adding a helper script to a profile is not a Connect solution.
- In the [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html),
  `x509-username-field ext:subjectAltName` extracts email `rfc822Name`, not DNS
  `dNSName`; it is not a substitute for hostname validation.

These are upstream compatibility findings, not a test of the installed Connect
binary. Recheck the released client's capabilities when support is announced,
then record the tested Connect/core versions and results. A server-only update
cannot add this client check.

Before declaring the blocker resolved, run the following against the actual
supported client and its generated profile. Local fixtures may use a disposable
test CA; deployment acceptance must also verify the public CA chain.

1. Accept a valid server certificate with the expected DNS SAN and no CN.
2. Reject a different DNS SAN signed by the same trusted CA, including when CN
   matches the expected name. Reject a missing DNS SAN without CN fallback.
3. Reject an untrusted chain, expired certificate, or incompatible EKU even when
   the DNS SAN matches. Rejection must occur before WEB_AUTH or tunnel access.
4. Reconnect to every cluster node and renew leaf certificates/keys without
   updating the profile or temporarily disabling verification.
5. Confirm wrong-name rejection after DNS/address changes and on a new handshake
   after reconnect. Preserve the expected identity across all configured remotes.
6. Test `tls-crypt-v2`, no client certificate, SAML browser login, and session
   expiry/reconnect together. An unsupported or ignored verification option must
   never be reported as an enabled security feature.

Identity rules: [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html).
