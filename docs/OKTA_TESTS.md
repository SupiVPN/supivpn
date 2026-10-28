# Real Okta acceptance checks

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The [Real Okta workflow](../.github/workflows/okta.yml) checks browser SAML login
and production-controller profile download with disposable PostgreSQL 18. It runs
weekly, manually before a release, and after relevant SAML, authorization,
profile, runtime/storage or harness changes reach main. It never runs untrusted
PR code with credentials; ordinary contributor checks use synthetic IdPs.
The normal Checks workflow also verifies the temporary CA boundaries and builds
the acceptance probe on PRs, without an Okta login or any external credentials.

## Configure the test environment

Use two dedicated developer-tenant SAML apps and a non-admin test user assigned
only to test resources. Sign both Response and Assertion with RSA-SHA256/SHA256,
and include a groups claim. An app-specific password-only exception may cover
that test user; do not relax shared or administrator MFA policy.

Keep the baseline app **unencrypted**. Configure its companion app with
**AES256_GCM** and **RSA_OAEP** assertion encryption and upload the public
certificate of a dedicated RSA recipient key. Both apps use the same endpoints
and test groups. Do not switch encryption on the baseline app between runs.

The harness verifies the actual browser response contains an EncryptedAssertion,
AES-256-GCM and RSA-OAEP. It rejects a plaintext fallback even if login would
succeed in optional mode. The production controller performs decryption,
signature verification, claim validation and profile authorization.

Configure:

- ACS: `https://test.supivpn.com:18443/saml/acs`.
- Audience: `https://test.supivpn.com:18443/saml/metadata`.
- DNS-only A record: `test.supivpn.com -> 127.0.0.1`; no AAAA/public listener.
  Okta returns the assertion through the browser and does not need to reach
  the runner itself.
- One group containing the test user and a different, empty group.

Create GitHub environment `okta-tests`, restricted to branch `main`:

| Type | Name | Value |
| --- | --- | --- |
| Environment variable | `OKTA_TENANT_ORIGIN` | HTTPS tenant origin, such as `https://integrator-example.okta.com` |
| Environment variable | `OKTA_METADATA_URL` | Public app metadata URL ending in `/sso/saml/metadata` on that tenant |
| Environment variable | `OKTA_ENCRYPTED_METADATA_URL` | Different public metadata URL for the encrypted companion app, on the same tenant |
| Environment variable | `OKTA_ENCRYPTION_CERTIFICATE` | Dedicated recipient certificate in PEM, matching the certificate uploaded to that app |
| Environment variable | `OKTA_TEST_ALLOWED_GROUP` | Exact group containing the test user |
| Environment variable | `OKTA_TEST_DENIED_GROUP` | Different, empty test group |
| Environment secret | `OKTA_TEST_USERNAME` | Dedicated test login / expected NameID |
| Environment secret | `OKTA_TEST_PASSWORD` | Its password |
| Environment secret | `OKTA_ENCRYPTION_PRIVATE_KEY` | Dedicated test recipient's unencrypted PKCS#8 RSA private key in PEM |

After reviewing the environment, set **repository** variable
`OKTA_LIVE_TESTS_ENABLED=true`. Until enabled, the job is intentionally skipped;
a skip is not live-test evidence. Once enabled, missing settings, invalid
credentials, MFA prompts, IdP outages and failed checks fail the job.

No Okta admin token, Cloudflare token, ACME account, persistent HTTPS key, GPG
key or working database credential belongs in CI. Use the approved transfer
procedure for test credentials; never paste them into issue/PR text.
The workflow changes no users, groups, apps, MFA policies or DNS. The extra
recipient key is limited to this encrypted test app; never reuse an operational
SAML, HTTPS, VPN or signing key. Transfer it directly into the encrypted
environment secret without printing it or including it in a commit or artifact.

The harness requires a matching, currently valid, non-CA RSA certificate/key
pair and fails when less than seven days of certificate validity remain.
Renew the dedicated pair and update the encrypted app's public certificate,
environment certificate variable and private-key secret together, with runs
paused during the change. Then run acceptance manually. This maintenance is
separate from each test run; CI has no permission to perform it.

## HTTPS and evidence

Each run generates a one-day CA, callback certificate and unrelated SAML recipient
key for plaintext-mode and wrong-key tests. The encrypted app's dedicated key
is written only into the private per-run directory, with mode 0600, and removed
from the process environment before launching acceptance. Only the Node test
process trusts the CA through NODE_EXTRA_CA_CERTS.
Each fresh Firefox profile imports the CA into its own NSS database.
ignoreHTTPSErrors remains false; no global or personal browser trust changes.
Fixture checks verify accepted trust, rejected missing trust and wrong hostnames.
Browser and helper subprocesses inherit neither the password nor the recipient
private key in their environments. The Go probe reads the key from its protected
per-run file through the production configuration loader.

The controller binds only 127.0.0.1:18443. PostgreSQL is an empty, disposable
supivpn_test database on loopback. The profile wrapping key exists only in memory
and is never used by a real VPN. The probe observes actual controller/storage
authorization rather than substituting a successful result.

Checks cover the following matrix with fresh password logins:

| App response | Controller mode | Expected result |
| --- | --- | --- |
| Plaintext | optional | Two different client profiles |
| Plaintext | required | Rejected before authorization or wrapping-key access |
| Encrypted | optional | Two different client profiles |
| Encrypted | required | Two different client profiles |
| Encrypted with an unrelated recipient key | optional and required | Rejected before authorization or wrapping-key access |
| Encrypted | disabled | Rejected before authorization or wrapping-key access |

Successful downloads check profile headers/format/CA/endpoint and exact server
name, unique client keys across all six downloads, and the bound profile ID and
secret format. Each issuance must persist an active record owned by the verified
SAML subject and username. SAML assertions and IdP passwords must not appear in
profiles. Checks also cover missing/wrong cookie rejection, replay and no
wrapping-key access before authorization.
Group denial is checked with both plaintext and encrypted assertions. Profile
issuance and rejected encryption must not create a VPN session.

Assertions, passwords, cookies, profiles and raw exceptions are not printed or
uploaded. No screenshots, video, HAR or traces are collected. Per-run keys,
downloads, metadata and browser profiles are removed afterwards; an always-run
cleanup also handles ordinary job failures. Hosted runners are disposable.

## Before a release

Dispatch Real Okta on main, wait for the acceptance job to pass, and record the
tested commit and run URL with release evidence. Verify that the release
candidate is that commit, or rerun after changes.

An external IdP failure is not automatically a product failure, but it is not a
pass. Diagnose the reported stage and tenant status, repair the setup and rerun,
or record the remaining limitation before deciding whether to release.

This test downloads profiles; it does not establish an OpenVPN tunnel. Native
OpenVPN and Debian VM tests cover that separately. It does not replace
production IdP policy, revocation or manual client acceptance.

## Local execution

Use Linux with the project's Go version, Node 24, OpenSSL and NSS certutil.
Install tooling before supplying test credentials to the execution process:

```bash
npm install --prefix local/okta-ci --no-save --ignore-scripts --no-audit --no-fund playwright@1.62.1
local/okta-ci/node_modules/.bin/playwright install firefox
node --test ci/okta/run.test.cjs
make okta-probe
node ci/okta/run.cjs
```

Provision the variables/secrets through your local procedure and start an empty
disposable PostgreSQL 18 first. Default port: 55432; OKTA_TEST_DB_PORT selects
another loopback port. The harness rejects a populated profile-login database.
Do not use working credentials/data or a personal browser profile.
