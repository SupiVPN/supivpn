# OpenVPN 2.7.9 upgrade review

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Reviewed on 21 November 2026. **Unreleased:** this branch tests upstream 2.7.9
and accepts both 2.7.8 and 2.7.9. Published SupiVPN v0.10.0 requires 2.7.8.
OpenVPN remains a separately installed, unmodified upstream process.

## Release notes and issues

The [2.7.9 release](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.9)
fixes inline/file credential parsing, a PUSH_UPDATE memory leak and several
Windows service issues. Management username hints require protocol level 6;
SupiVPN continues to negotiate level 5. No profile format change is needed.

| Upstream issue | Relevance and remaining limit |
| --- | --- |
| [#1140](https://github.com/OpenVPN/openvpn/issues/1140), fixed | Overlong inline usernames could spill into the password field. SupiVPN uses fixed-length random profile IDs and secrets; real bound-profile login tests cover their parsing. |
| [#1148](https://github.com/OpenVPN/openvpn/issues/1148), open | A Linux TCP listener can spin on file-descriptor exhaustion and delay timers. It also affects DCO. Keep `max-clients` explicitly below the effective descriptor limit with headroom for listeners, management, logs and other descriptors; apply connection limits at the network boundary. This is mitigation, not an upstream fix. The shipped example uses 16 clients; custom large deployments must review their limits. |
| [#1127](https://github.com/OpenVPN/openvpn/issues/1127), closed | The unauthenticated pending-TCP assertion was reported against development 2.8 code, explicitly not 2.7.8. Do not substitute a development build for the reviewed stable archive. |
| [#1146](https://github.com/OpenVPN/openvpn/issues/1146), open | DCO clients can omit a management status response while reconnecting. Tests disable DCO and do not establish DCO compatibility. |
| [#1151](https://github.com/OpenVPN/openvpn/issues/1151), open | Windows Community 2.7.9 regression with `route-method exe`. SupiVPN templates do not set this option; Windows GUI acceptance is separate. This report is not evidence about the distinct Connect client. |
| [#1069](https://github.com/OpenVPN/openvpn/issues/1069), open | Documents the 2.7 management real-address protocol prefix. SupiVPN has protocol-aware address tests and UDP/TCP management tests. |

This dated review does not establish that OpenVPN has no remaining flaws. In
particular, upgrading to 2.7.9 does not resolve #1148. TCP stays optional and off
by default. The tests do not enable DCO or patch upstream code.

## Source verification

The archive and detached signature come from the
[official release directory](https://build.openvpn.net/downloads/releases/).
The signing primary matches the
[published fingerprint](https://community.openvpn.net/Downloads/Verify%20signature).

```text
Primary: F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7
Signer:  33DA8C9EAE0EAE8C73172C10822F6DF096D04874
Archive: openvpn-2.7.9.tar.gz
SHA256:  c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1
```

Both [ci/Dockerfile](../ci/Dockerfile) and the
[Debian test builder](../ci/debian/Dockerfile) pin this checksum. The retained
2.7.8 local compatibility run used the existing ARM64 test image, built with
its previously verified archive checksum
`c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36`.

## Package availability and upgrade

Debian 13 [trixie-backports](https://packages.debian.org/trixie-backports/openvpn)
still provides `2.7.8-1~bpo13+1` on ARM64 and AMD64 at review time. The new
SupiVPN package therefore accepts distribution revisions of **2.7.8 or 2.7.9**;
setup and key bootstrap reject other versions, prereleases and numeric suffix
lookalikes. This is not a promise of arbitrary 2.7.x compatibility.

Keep the documented 2.7.8 Debian installation path until a reviewed 2.7.9 package
is available for the target distribution. Do not force dependencies, mix in
testing/unstable repositories, or install the disposable CI OpenVPN fixture on a
working server. The test default changes to 2.7.9 without silently requiring an
unavailable distribution package. Once released, update SupiVPN before selecting
2.7.9; the published v0.10.0 package dependency does not accept it.

Schema 12, SAML ownership checks, active/blocked state, tls-crypt-v2 wrapping keys,
profile credentials and UDP/TCP configuration remain unchanged. Existing bound
profiles need no reissue. Drain and update one node at a time, verify management
readiness and a fresh SAML connection, then continue. Roll back with the prior
SupiVPN/OpenVPN pair and retained keys/configuration if needed. Updating only
Lambda or the SupiVPN archive does not patch OpenVPN or preserve active tunnels
across a daemon restart.

See [dependency verification](DEPENDENCY_UPGRADE.md#verification-and-upgrade-boundaries)
for local results and the PR for hosted CI. Linux/OpenSSL tests do not
establish native Connect, Windows, FreeBSD or DCO acceptance.
