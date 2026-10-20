# OpenVPN Connect: session expiry and new login

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

This isolated harness checks automatic reconnection after **120 seconds**.
It uses no AWS, Okta, or deployment keys. Connect itself opens the browser;
the harness neither opens URLs nor confirms SAML automatically.

Requirements: Docker/TUN and the local OpenVPN 2.7.8 image from [BUILD.md](../BUILD.md).
Run from the project root:

```sh
make test-connect
```

After `READY_FOR_CONNECT`, import the new
**local/connect-test/connect-test.ovpn**.
Old test profiles do not work: every run generates temporary keys.
The endpoint is `127.0.0.1:11194`; leave Server Override empty in Connect.

1. Connect, allow the temporary `localhost:18443` HTTPS certificate for this test
   only, and click authorize. No password is needed.
2. Run `ping 10.203.0.1` and leave Connect connected.
3. After 120 seconds, the tunnel should end and ping should stop.
   Connect should reconnect automatically and open a **new** browser login.
   Do not copy URLs or manually click reconnect.
4. Authorize the new login. The harness prints `RECONNECTED` with a new CID.
   Verify that ping resumes and the **Authentication required dialog closes**.
5. After 30 seconds of a healthy new session, the harness finishes with PASS.

PASS confirms a new CID/ticket, two browser requests, old-tunnel DISCONNECT,
and release of its IP. The new tunnel may receive the same IP.
The operator verifies automatic browser launch and dialog state;
the test does not inspect the Connect UI.

**Manual Mac check on 2026-09-22: PASS.** After 120 seconds, the old tunnel ended
and Connect automatically reconnected and opened a new SAML login.
The operator confirmed that ping resumed after authorization and the
`Authentication required` dialog closed. The harness separately confirmed
CID 0 -> 1, a new ticket, release of the old IP, and 30 seconds of a healthy
new session. Reusing the IP was valid: this was a new connection, not renewal
of the previous session. The container exited with code 0 and was removed automatically.

The harness uses a local controller. PostgreSQL integration tests cover cluster
slots/cancel; real IdP policy is tested in deployment.
For a negative check, do not authorize the second login: VPN access must remain
unavailable, and the harness's positive scenario will not report PASS.

UDP/11194 and HTTPS/18443 are published only on loopback; the Mac default route
and DNS are unchanged. The container is removed on completion or after the
20-minute timeout. Remove the test profile from Connect afterward.
This interactive test is not part of `make test-all`.
