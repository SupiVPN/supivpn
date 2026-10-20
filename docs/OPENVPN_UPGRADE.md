# OpenVPN 2.7.8 upgrade review

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Reviewed on 2026-10-09 for SupiVPN v0.1.1. OpenVPN remains a separately installed
process, not part of the SupiVPN release archive.

## Upstream changes and issues

The [2.7.8 release](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.8)
includes fixes for certificate-subject NUL bytes (CVE-2026-84790), DNS search-list
underflow (CVE-2026-88964), Windows command expansion (CVE-2026-84256), and a
tls-crypt-v2 client handshake error. It also fixes DCO lifecycle races and a
server broadcast-queue deadlock. OpenSSL now rejects certificate subjects
containing NUL bytes; malformed certificates may therefore stop working.

The issue review found no confirmed new blocker for the tested Linux/OpenSSL,
non-DCO configuration. This is a dated assessment, not a guarantee:

- [#1111](https://github.com/OpenVPN/openvpn/issues/1111): the reported DCO
  key-install failure could terminate the server; upstream marks it fixed.
- [#1117](https://github.com/OpenVPN/openvpn/issues/1117): Windows DNS suffix
  behavior predates 2.7.8 and is not evidence of a new Linux server regression.

The automated tests disable DCO. They do not validate kernel DCO, Windows,
FreeBSD, or the OpenVPN Connect browser UI. Test those environments separately
when they are deployment requirements.

## Source verification

The upstream source archive and detached signature were obtained from
[the official release directory](https://build.openvpn.net/downloads/releases/).
The signature was verified against the fingerprint published in the
[OpenVPN verification instructions](https://community.openvpn.net/Downloads/Verify%20signature):

```text
OpenPGP: F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7
Archive: openvpn-2.7.8.tar.gz
SHA256:  c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
```

The same source checksum is pinned in [ci/Dockerfile](../ci/Dockerfile).
CI images contain Go 1.27.2 and PostgreSQL 18.6 with official base images pinned
by digest. Runtime and build dependencies are checked independently.

## Validation

Local unit/race tests, vet, PostgreSQL integration, XMLSec interoperability,
bounded XML and signed-SAML fuzzing, module integrity, and source/binary
govulncheck scans passed. No known Go vulnerabilities were reported.

Real OpenVPN tests passed on Linux ARM64 and AMD64, covering:

- tls-crypt-v2 key generation interoperability, missing/wrong/tampered keys;
- SAML authorization, group priority, expanded pools, and no-group rejection;
- delayed browser authorization, tunnel establishment, and disconnect;
- foreground/daemon management startup;
- TLS renegotiation without extending the authorized session;
- process failure, lease expiry, session expiry, and reconnect across two nodes.

Upstream unit and system tests are also run in disposable containers. Network
tests require NET_ADMIN and run after the image build, with no host networking.
The upstream `t_client` and `t_server_null` suites require external fixture
configuration and are not included. CI gates the final release artifacts again.

## Upgrade contract

This is a patch release: schema 9, configuration fields, bundle format 3, SAML
claims, and tls-crypt-v2 key format remain unchanged. The profile CLI requires
exactly OpenVPN 2.7.8 and refuses older or unreviewed versions.

Update the node's separately installed OpenVPN package as well as SupiVPN.
Retain the existing wrapping key and client profiles. Drain and update one node
at a time, verify its management readiness and a new SAML connection, and then
continue with the next node. Updating only the downloaded SupiVPN bundle does
not patch the OpenVPN daemon. Existing server-identity and key-rotation
limitations in [SECURITY_MODEL.md](SECURITY_MODEL.md) remain open.
