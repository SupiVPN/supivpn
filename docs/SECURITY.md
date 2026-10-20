# Dependencies and SAML verification

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Verified **2026-09-22**, Go **1.27.1**, govulncheck **1.8.0**.
Reproduction: [BUILD.md](../BUILD.md), `make security deps-check`.
This reports completed checks, not an independent audit.
All component trust boundaries and open blockers: [SECURITY_MODEL.md](SECURITY_MODEL.md).
Fencing/recovery findings R1–R3 were fixed; durable maintenance and operator
resume/resolve preserve budgets. On September 22, 2026, make build vet security
and the full PostgreSQL 18 integration suite passed with the race detector.
Govulncheck found no known vulnerabilities in macOS/Linux source/tests or any of
the five binaries. [Evidence and limits](SECURITY_REVIEW.md).
Live AWS Stop/Start and rollout were not performed.

## Current dependencies

- PostgreSQL: **pgx/v5 v5.11.0** retained; the driver was not rewritten.
- XML DOM: **etree v1.8.0**. RSA, SHA-256, and X.509 use Go's standard library.
- SAML Web SSO and required XMLDSig verification: custom `internal/saml`.
- Official AWS SDKs retained; **aws-lambda-go v1.55.1** and **smithy-go v1.28.2** updated.
  EC2 fencing uses **service/ec2 v1.335.0**, only in the AWS adapter.
- Removed crewjam/saml, goxmldsig, jwt/v4, clockwork, xml-roundtrip-validator,
  and x/crypto. The earlier module-only report about unused OpenPGP no longer
  applies to the current graph.

Full versions/licenses: [go.mod](../go.mod),
[THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES.md), and
[THIRD_PARTY_LICENSES.txt](../THIRD_PARTY_LICENSES.txt).
The remaining direct third-party dependencies outside AWS and Go are etree and pgx.
Transitive pgpassfile, pgservicefile, and puddle are required by pgx.

`go list -m -u -retracted all` found no newer versions for modules used by current
Go packages. The wider graph still has updates for dependencies' test/tool
modules (kr/pretty, objx, testify, x/tools); these are absent from deployment
binaries. `make deps-check` reports them rather than hiding them with an ignorelist.

## Supported SAML/XMLDSig

This is a restricted Web SSO profile, not a general replacement for a SAML/XMLDSig library.

- SP-initiated AuthnRequest via HTTP-Redirect; HTTP-POST responses only.
  One expected request ID, exact ACS/Destination/InResponseTo/Issuer/Audience.
  IdP-initiated flows, Artifact binding, SLO, XML encryption, and signed
  AuthnRequests are unsupported.
- One Assertion; signed Response, Assertion, or both.
  Every present signature must verify.
- **RSA PKCS#1 v1.5 + SHA-256**, SHA-256 digest, **Exclusive XML C14N 1.0 without
  comments**, optional InclusiveNamespaces PrefixList.
- Exactly one Reference `#ID` targeting the verified element.
  Exactly two transforms: enveloped-signature → exclusive C14N.
  Empty/external URIs, multiple references, XPath, implicit transforms,
  SHA-1, ECDSA, RSA-PSS, and inclusive C14N are rejected.
- Trusted RSA keys come only from locally configured IdP metadata.
  Response KeyInfo adds no trust. Checks enforce RSA 2048–8192, certificate
  validity, digitalSignature when KeyUsage is present, and metadata validUntil
  when specified.
- Authorization reads the tree produced from verified canonical bytes.
  Verification preserves namespace context; duplicate IDs/attributes, nested or
  substituted Assertions, ambiguous singleton elements, and prefixed protocol
  attributes are rejected.
- Pre-DOM limits: XML 1 MiB, depth 64, elements 512, tokens 4096, attributes 4096
  total / 64 per element. Canonical output is capped at 4 MiB.
  DTDs, external entities, and processing instructions other than an initial
  XML declaration are rejected.
- UTF-8, ASCII XML names/IDs, absolute namespace URIs.
  Literal LF/CR/TAB in attribute values is rejected; numeric references work.
  This deliberately limits compatibility. Whitespace outside the root is not
  part of the signed subtree.
- The controller additionally checks bearer confirmation, assertion/session
  deadlines, browser binding, groups, one-time pending login, and replay.
  PostgreSQL preserves these guarantees across controller processes.

After replacing libraries, repeat live target-IdP login, group checks, and profile
download: synthetic fixtures do not prove compatibility with every assertion
variant from a provider.

## Additional security regressions

[Sessions and fencing](SESSIONS.md): cluster limits of 1/2 under concurrent
SAML logins, lost ACK/cancel, expiry without unsafe slot release, cooldown,
EC2 API failure, legacy grants during migration, and node return.
Automatic recovery also tests shared heartbeat loss, concurrent controllers,
loss of the healthy neighbor, confirmed stop before Start, new generation,
stable readiness, global start budget, and cascade blocking after a failed cycle.
The SDK is mocked; these tests never stop or start real EC2 instances.

After recovery changes on September 22, 2026, build, vet, and the full PostgreSQL
integration/race suite passed. The latest native OpenVPN 2.7.7 run also passed.
An earlier `expanded-core` run failed once with HTTP 410 due to unavailable
management; the instability's cause remains unknown, and a later PASS does not
prove it fixed. Old session renewal was removed. The manual Mac reconnect
scenario passed on September 22, 2026: [CONNECT_TEST.md](CONNECT_TEST.md).
A separate native test proves OpenVPN termination after lease expiry and client
reconnect to another node. EC2 Stop/Describe uses a mock SDK.

`make test-security` runs local adversarial tests with the race detector.
It is part of `make security`, alongside known-vulnerability scanning.

- Malformed assertions are signed **after** modification: duplicate Subject,
  NameID, Conditions/Audience, unsupported conditions, and complex/nil claims.
  Signature validity is proved separately so digest rejection cannot hide a
  missing semantic check. Response, Assertion, and double signatures are covered.
- IdP key rotation: before/during overlap and after old-key removal; empty trust
  store; foreign KeyInfo; expired/future certificates; encryption-only KeyUsage;
  RSA 1024; metadata keys with use=encryption.
- Changing unsigned InResponseTo around a signed Assertion cannot authorize
  another pending login. Both legitimate logins still work after rejection.
- Agent API: escaped/case-duplicate JSON keys, overflowing/non-integer CID,
  command/control-character injection, and header-based node impersonation.
  All six operations, including heartbeat, require trusted transport identity;
  malformed requests neither call the store nor break the next valid request.
- Controller → agent replies reject duplicate/case-alias keys, null, and missing
  node/generation/CID/KID/deadline fields. Before the fix, 12 regressions showed
  the transport decoder accepted these ambiguities; all pass after the fix.
  This strengthens the transport boundary: later agent checks already rejected
  many such decisions, and these tests did not demonstrate a general SAML bypass.
- Replay, concurrent redemption, controller replacement, stale/foreign node
  decisions, late fetch after CID reuse, and safe profile download checks remain.

`make test-xmlsec` additionally checks namespace rebinding, default namespaces,
comment/text boundaries, and escaping against independent libxml2/XMLSec in both
directions. Claims modified after independent signing must be rejected.
`make fuzz` checks C14N idempotence and invariance of all accepted signed claims
under XML mutation in two separate bounded runs.

Scenarios follow [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
guidance on signature wrapping, trust anchors, request correlation, and replay.
This is not full XSD validation, compliance certification, or an independent
audit of our SAML/XMLDSig implementation.

## Checks

- 2026-09-22: build/vet, unit/race, and PostgreSQL 18 integration — PASS.
  Native OpenVPN 2.7.7 — PASS, including expiry → DISCONNECT → new CID/SAML on
  the same node without restart. Host/controller Terragrunt validate — PASS.
  `make test-connect` — PASS: expiry, old IP release, new CID/ticket, and new SAML
  login. The operator confirmed automatic browser opening, ping recovery, and
  closure of the Mac `Authentication required` dialog.
- New session model: finite deadline or explicit unlimited, signed IdP cap,
  TLS rekey without extension, per-client timeout, strict API envelope.
  Migration 6 removes renewal. OpenVPN Connect automatic reconnect/UI is
  checked through a separate interactive test environment.
- `make test-all` after sessions/heartbeat/fencing — PASS.
  Official EC2 SDK added; core uses a provider interface.
- Unit/race and vet, including integration code — PASS.
- PostgreSQL 18.3 integration — PASS: migrations, runtime grants/DDL denial,
  TLS, reconnect, credentials on reconnect, replay/ACK, remote controller,
  profiles, and cluster.
- A separate real restart of disposable PostgreSQL in an earlier run — PASS:
  the same pool/controller recovered, preserving the decision and replay protection.
- XMLSec/libxml2 independently verifies our signatures; SupiVPN verifies XMLSec
  signatures. All six scenarios, including namespace/text edge cases — PASS.
- Real OpenVPN 2.7.7: tls-crypt-v2, SAML, group pools, denials, and two-node failover
  with one profile — PASS.
- Two 20-second fuzz runs: 349,941 parser/C14N executions and 45,609 signed-response
  mutations — PASS. These bounded runs do not prove the absence of all defects.
- Linux amd64 agent, VM controller, profile CLI, migrator, Lambda bootstrap, and
  ZIP built.
- govulncheck: macOS arm64/Linux amd64 source/tests and all five deployment
  binaries — **No vulnerabilities found**.
- `go mod verify` — PASS.

Automated tests did not contact RDS, AWS APIs, live Okta, or the client UI.
Docker stopped and removed the disposable PostgreSQL container after the run.

During one `test-all`, native `expanded-core` failed at the initial SSO GET.
Twenty separate repetitions and a repeated full native suite passed.
The isolated failure's cause remains unknown; safe HTTP status/readiness
diagnostics were added without assertions, cookies, or tokens.
The Makefile does not automatically retry failed tests.

Dependency scanning does not verify custom canonicalizer correctness, host system
packages, or cloud network configuration.

## Why a narrow XMLDSig implementation

Reviewed [goxmldsig issues](https://github.com/russellhaering/goxmldsig/issues).
[ECDSA encoding #163](https://github.com/russellhaering/goxmldsig/issues/163) and
[inclusive C14N #92](https://github.com/russellhaering/goxmldsig/issues/92) concern
unsupported features; this does not mean those upstream issues were fixed.
The Reference-selection error class
([CVE-2026-33487](https://github.com/russellhaering/goxmldsig/security/advisories/GHSA-479m-364c-43vc))
is addressed by one exact Reference and a negative regression test.
Explicit budgets bound XML parser/canonicalizer work.

The absence of individual upstream copyright headers did not mean absence of a
license: goxmldsig had an Apache-2.0 LICENSE. Removing the dependency does not
change rights for older versions or artifacts already distributed.

Specifications for the supported subset:
[SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
[XMLDSig](https://www.w3.org/TR/xmldsig-core1/),
[Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/).
