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

## Server URL import

`TestConnectServerURLManual` is a separate, opt-in native Connect acceptance
fixture. It runs the product controller, PostgreSQL profile registry and signed
SAML flow with a synthetic IdP. It does not use a real IdP account or establish
a VPN tunnel. The Debian VM test checks both VPN listeners separately.

Use a disposable `supivpn_test` PostgreSQL database as described in
[BUILD.md](../BUILD.md). Choose a test hostname resolving to `127.0.0.1` and a
matching HTTPS certificate already trusted by Connect and the browser. The
fixture binds only `127.0.0.1:18443`; it never changes DNS or system trust. Do not
disable certificate verification to obtain a successful result.

```sh
make integration PKG=./internal/agent RUN='^TestConnectServerURLManual$' \
  TEST_VERBOSE=-v TIMEOUT=22m \
  SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/supivpn_test?sslmode=disable' \
  SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1 \
  SUPIVPN_TEST_CONNECT_IMPORT=1 \
  SUPIVPN_TEST_CONNECT_ORIGIN='https://vpn.example.test:18443' \
  SUPIVPN_TEST_CONNECT_CERT=/absolute/path/to/test-fullchain.pem \
  SUPIVPN_TEST_CONNECT_KEY=/absolute/path/to/test-key.pem
```

1. After `READY_FOR_CONNECT_SERVER_URL`, enter that base URL in Connect's
   **Server URL** field. Do not import a file or open the SAML page manually.
2. Confirm that Connect opens the browser. Follow **Continue with SAML** when
   displayed, then **Authorize test identity** on the isolated IdP page.
3. Use **Open in OpenVPN Connect** on the result page and approve the browser's
   request to open the application. Finish importing the new test profile.
4. Record the Connect version/platform and whether the native UI shows a
   successfully imported profile. Remove only that newly created test profile.

`SERVER_FLOW_COMPLETE` proves discovery, signed SAML, grant redemption and a
persisted active profile. It does **not** prove that the native client accepted
the profile: the UI observation is a separate required result. An unattended
run skips this test unless explicitly enabled; a skipped run is not acceptance.
The fixture times out after 20 minutes and closes its HTTPS listener. Stop the
disposable database after checking the result.

Do not capture or publish SAML form contents, the one-use import URL, or the
profile's secret. Server logs deliberately omit those values.

**Manual macOS arm64 check on 2026-10-24: PASS**, Connect 3.9.0 (6050).
Connect discovered the service and opened the browser. The operator completed
the synthetic SAML and application handoff and confirmed successful import.
The fixture reported `SERVER_FLOW_COMPLETE` and exited successfully. HTTPS
certificate verification remained enabled. This is an import result only;
it does not establish a native Connect tunnel or real-IdP acceptance.
