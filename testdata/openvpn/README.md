# SupiVPN — native OpenVPN tests

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../../LICENSE) for copyright ownership and licensing terms.

Run from the repository root. Tests need a disposable Linux environment with OpenVPN
2.7.8, TUN support and NET_ADMIN. They do not need a cloud account or a live IdP.

The checked-in `ci/Dockerfile` builds OpenVPN 2.7.8 from a checksum-pinned
upstream source archive. The build context contains only CI tooling; no private
installer, cloud credentials or deployment configuration is required.

```bash
make openvpn-image
make test-openvpn
# Optional compatibility run on Apple Silicon (emulated and slower):
make openvpn-image test-openvpn ARCH=amd64
```

The test creates ephemeral TLS/IdP/tls-crypt-v2 keys. No production secrets or live
IdP are used. OpenVPN server and clients run inside the same disposable container;
TUN interfaces and NET_ADMIN apply only there. Logs stay in memory and are never
dumped, including on failure.

Coverage:

- Real native key generation, independent client keys, persistent server key.
- Go-generated timestamp keys accepted by real OpenVPN 2.7.8; wrong wrapping key
  and tampered tag rejected before TLS/SAML, valid key still requires a VPN group.
  Rebuild the test binary after changes to the suite or agent.
- Missing/wrong keys cannot reach TLS, management CONNECT or WEB_AUTH.
- Real management version negotiation, pending browser authentication and ACK.
- Signed synthetic SAML, dev/core pools, both-group priority and no-group refusal.
- Actual client PUSH_REPLY with the selected IP and established tunnel.
- The deployed learn-address binary is used unchanged.

The Community CLI requires synthetic auth-user-pass values when omitting a client
certificate. OpenVPN Connect uses CLIENT_CERT=0 and needs no such file. The test
values do not authorize access: signed SAML remains mandatory.

This is not an OpenVPN Connect UI/Okta live test. Repeat that check in the target deployment.

`TestOpenVPNClusterFailover` starts two real daemons with one wrapping key,
uses one issued profile, stops node 1 and verifies automatic reconnect + a new
SAML login with an address from node 2. Its local UDP relay and 1/3-second
keepalive do not simulate AWS NLB timing. See [HA](../../docs/HA.md).
