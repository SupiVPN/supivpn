# SupiVPN security model

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Review date: **2026-09-22**. This working document covers threats, checks, and open
tasks. Passing a test or scanner does not mean the whole deployment is secure.
Current status: **production-readiness blockers remain open**.

## Assets and threats

An attacker may be anonymous, an IdP user without a VPN group, a member of a
less privileged group, or the holder of a copied profile. They may modify requests,
replay responses, impersonate DNS/servers, issue concurrent requests, and cause
failures. Dependency, build, operator account, and VPN node compromise are also
considered.

Critical assets include access decisions, group → CIDR mappings, node identity,
IdP metadata, wrapping/TLS keys, database credentials, client profiles, artifacts,
and configuration. Operator code/configuration, the IdP, controller, and PostgreSQL
are trusted. Root compromise on a node allows forwarding/source-address changes;
group addresses alone do not protect against a compromised gateway. Write access
to the authorization database is also outside application replay-protection guarantees.

## Trust boundaries and evidence

| Boundary/component | Required property | Local evidence | Deployment checks still required |
| --- | --- | --- | --- |
| Browser → SAML controller | Trusted IdP signature, exact issuer/audience/recipient/request, cookie binding, groups, and deadlines | `auth_security_test.go`, `auth_test.go`, `internal/controller` | Real IdP claims, MFA policy, access changes/revocation |
| XML → authorized claims | One assertion/reference, ambiguity rejected, bounded parser work | `internal/saml/security_test.go`, XMLSec, two fuzz targets | Independent parser/C14N/XMLDSig review |
| Browser → profile download | One-time SAML login, separate pending state, key read only after authorization, no-store | `internal/controller`, `internal/profile`, `profile_download_integration_test.go` | CDN caching/logs, VPN server trust, stolen-profile response |
| Node → controller | Identity from IAM context or kernel peer UID, never request body/headers | `internal/gateway`, `internal/vm`, `internal/agentapi` | IAM invoke boundaries, SGs, Unix ownership, origin bypass prevention |
| Controller → node | Complete unambiguous decision: node/generation/CID/KID/deadlines; late replies cannot authorize another session | `internal/agentclient/security_test.go`, `remote_agent_test.go` | TLS endpoint identity and configuration delivery |
| Controller → PostgreSQL | Parameterized queries, transactions/replay, bounded timeouts, separate runtime/migrator/owner roles | `postgres_integration_test.go`, `ownership_integration_test.go`, reconnect/credentials tests | TLS verify-full, CA, credentials/backup/restore, database privileges |
| VPN client → OpenVPN | tls-crypt-v2, SAML before access, IP only from selected pool, source-IP spoofing protection | Native OpenVPN 2.7.8, group/cluster/learn-address tests; [upgrade review](OPENVPN_UPGRADE.md) | Server identity, SG/NAT/reverse routes, group isolation, IPv6/DNS leaks |
| Wrapping key → client profile | Shared server key never enters the profile; a fresh client key is issued | `internal/profile`, native interoperability | Rotation/revocation, secret-store isolation, backup |
| VM/Lambda lifecycle | Fail closed on dependency loss, bounded requests, separate public/agent listeners | `internal/vm`, `internal/controlruntime`, agent/cluster integration | Process privileges, systemd sandbox, IMDS, patching, load |
| Public → recovery isolation | Separate executable, invocation boundary, IAM and restricted SQL privileges | `isolation_integration_test.go`, `isolated_handler_test.go`, gateway isolation tests | Three execution roles/secrets, permission denial, schema-10 readiness and controlled cutover, independent concurrency; [contract](LAMBDA_ISOLATION.md) |
| Fencing/recovery → provider power | Uncertain tunnels retain slots; Stop/Start target current nodes only, with durable guards | `recovery_integration_test.go`, `session_limits_integration_test.go`, `operator_integration_test.go` | Real cloud failures/rollout, end-to-end readiness, alarm delivery |
| Build/dependencies → release | Verified modules, known vulnerability checks, reproducible artifact contents | govulncheck, `deps-check`, packager tests | Release signing/provenance, trusted delivery, OS/OpenVPN/image scanning |
| Internet → edge | Rate limits, concurrency/body limits, cost controls | HTTP/parser limits and generic errors | CDN/API rules and bypasses, load/DoS tests, alerts |

Test paths are relative to the repository root. A listed test covers a specific property;
it is not an audit of the whole component. Local Terraform review checks intended
configuration only; deployed IAM/SG/CDN/OS rules require separate verification.

## Open production-readiness tasks

Cluster session limits and stalled-node behavior are described in
[SESSIONS.md](SESSIONS.md). TTL alone does not release slots: disconnect,
controlled restart, or confirmed fencing is required. EC2 adapter tests use mocks;
real stop operations and IAM/EC2/database failures need deployment testing.

1. **VPN server identity.** The current `examples/client.ovpn.example` trusts the
   CA and validity period, but does not verify a specific VPN server. Explicit
   KU/EKU directives are omitted for [client compatibility](PROFILES.md#client-template-compatibility).
   Bound downloads additionally enforce an exact CN match before sending their
   profile proof. From v0.10.0, all supported admission requires these bound
   profiles; the explicit v0.9.1 legacy exception ends with v0.9.x. Follow the
   [migration procedure](PROFILE_BINDING.md#explicit-legacy-transition-through-v09x)
   before upgrading. The raw template alone is not an issued profile.
   The selected direction (2026-10-05) is a public CA plus client-side DNS SAN
   verification, without CN fallback. This is not implemented: stock OpenVPN
   Connect profile support is a blocker. See the [client compatibility evidence
   and acceptance criteria](TLS_CRYPT_V2.md#planned-dns-san-verification).
   Acceptance: the correct server is accepted; another server with a certificate
   from the same CA is rejected; renewal and node failover never create an
   unverified interval or require pinning each renewed leaf certificate.
2. **PostgreSQL identity.** `require` remains the agreed compatibility default;
   it encrypts without authenticating the database server. The controller and
   migrator support `database_tls.mode=verify-full`, a CA bundle and a separate
   trusted `server_name` when connecting through a DNS alias. Local pgx handshake
   tests cover wrong CA/name, expiry, plaintext refusal, renewal and reconnect.
   Deployment must still enable verification, deliver the CA and trusted name,
   and test live database failover. See [configuration and limitations](POSTGRES.md#configurable-database-tls).
3. **Independent SAML/XMLDSig audit.** The custom implementation has a narrow
   subset, negative tests, fuzzing, and XMLSec interoperability. These do not
   replace independent review of canonicalization, wrapping, schema assumptions,
   time conditions, and target IdP integration.
   The internal October 23 review adds bounded inclusive-prefix handling,
   signature-before-reference processing and VPN browser confirmation enabled
   by default. [Setting `vpn_login_confirmation=false`](IDENTITY_PROVIDER.md#vpn-login-confirmation)
   removes that step: a relayed link can use the victim's existing IdP session
   to authorize another client's connection without SupiVPN confirmation.
   A confirmation is not proof that the browser and requesting VPN client are
   on the same device. A user who deliberately approves a relayed login can
   still authorize another client's connection. Stronger client/browser binding
   needs a separately designed client-assisted mechanism; neither MFA nor
   assertion encryption establishes that binding.
4. **Keys and compromise response.** Verify procedures for lost wrapping/TLS/IdP/
   database/agent credentials. Individual bound profiles can be blocked for new
   and incomplete admission; blocking does not terminate an established tunnel
   or prevent use of its wrapping key at the OpenVPN pre-auth layer. Use the
   session-disconnect action when immediate termination is needed. Automatic
   wrapping-key rotation with overlap is not implemented. A profile alone cannot
   authorize VPN access without matching SAML ownership, but theft still matters.
5. **Live network and operational checks.** Test group isolation, metadata/management
   endpoints, DNS/IPv6 leaks, origin bypass, recovery/rolling rollback, resource limits,
   and alerting in the target environment. Review OS/OpenVPN/container versions and
   privileged processes; the Go scanner does not cover them.
6. **Fencing/recovery and maintenance acceptance.** R1–R3 are fixed; operator
   resume/resolve uses CAS, power checks, and idempotency. Live cloud failure/rolling
   replacement tests and alarm delivery are still required. See the
   [contract](RECOVERY.md) and [residual risks](SECURITY_REVIEW.md).
   Never reset blocked states/slots through SQL or treat automatic_recovery=false
   as maintenance.

Earlier TLS relaxations are documented explicitly. Migrating them changes
CA/endpoint or client-profile requirements and needs coordinated deployment.
Unit tests do not close these issues.

## Changes and releases

For each change, identify the trust boundary and failure behavior. Reproduce a
discovered bypass with a test before fixing it; include a positive control,
checks against unintended authorization, and concurrency/failure between steps
where appropriate. Never add fallback that weakens authorization when a dependency fails.

Before release, run the commands in [BUILD.md](../BUILD.md): unit/race, vet,
security/dependencies, integration, XMLSec, native OpenVPN, and bounded fuzzing.
Record artifact versions, deployment test results, untested scenarios, and open
risks separately. Do not hide failed tests through retries.
Current report and limitations: [docs/SECURITY.md](SECURITY.md).

Do not log assertions, cookies, tickets, keys, DSNs, or raw dependency errors.
Use failure categories, non-secret correlation IDs, and count/latency metrics.
Review proxy/CDN/API Gateway access logs separately because tickets appear in URLs.
