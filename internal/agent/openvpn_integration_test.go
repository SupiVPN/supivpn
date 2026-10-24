// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
)

//go:embed testdata/server.conf.example
var openVPNServerTemplate string

//go:embed testdata/client.ovpn.example
var openVPNClientTemplate string

// Logs remain in memory: they can contain a one-time WEB_AUTH URL. Never dump
// their contents on failure. Inspect only expected protocol markers.
type protocolLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *protocolLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *protocolLog) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.b.String(), s)
}

func (l *protocolLog) categories() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var observed []string
	for _, tag := range []string{"Options error", "You must define", "auth-user-pass", "Cannot open TUN/TAP",
		"VERIFY ERROR", "VERIFY KU ERROR", "VERIFY EKU ERROR", "AUTH_FAILED", "UDPv4 link remote",
		"Peer Connection Initiated", "TLS Error", "ERROR", "tls-crypt unwrap error",
		"certificate verify failed", "certificate signature failure", "unsupported certificate purpose",
		"OpenSSL", "TLS handshake failed", "unsupported", "Unrecognized option",
		"AUTH_PENDING received", "WEB_AUTH:external:", "PUSH_REQUEST", "PUSH_REPLY", "ifconfig ",
		"Initialization Sequence Completed", "learn-address", "MULTI: Learn", "MULTI: primary virtual IP",
		"Failed running command", "Exiting due to fatal error", "SIGTERM", "SIGUSR1", "process restarting",
		"SIGUSR1[soft,no-push-reply]", "SIGUSR1[soft,ping-restart]",
		"SIGUSR1[soft,server-pushed-connection-reset]", "SIGTERM[soft,auth-failure]"} {
		if strings.Contains(l.b.String(), tag) {
			observed = append(observed, tag)
		}
	}
	return observed
}

func TestProtocolLogCategoriesWithholdPayloads(t *testing.T) {
	log := &protocolLog{}
	log.Write([]byte("Info command was pushed by server ('WEB_AUTH:external:https://idp.example.test/login/fixture-only')\n" +
		"PUSH_REPLY,ifconfig 10.203.0.65 255.255.255.0,auth-token fixture-only\n"))
	if got := strings.Join(log.categories(), "|"); got != "WEB_AUTH:external:|PUSH_REPLY|ifconfig " {
		t.Fatal("protocol diagnostics must contain only fixed category labels")
	}
	log = &protocolLog{}
	log.Write([]byte("SIGUSR1[soft,no-push-reply] received, process restarting\n" +
		"unrecognized payload must stay private\n"))
	if got := strings.Join(log.categories(), "|"); got != "SIGUSR1|process restarting|SIGUSR1[soft,no-push-reply]" {
		t.Fatal("restart diagnostics must contain only fixed category labels")
	}
	log = &protocolLog{}
	log.Write([]byte("unrecognized payload must stay private"))
	if len(log.categories()) != 0 {
		t.Fatal("unrecognized log contents exposed by protocol diagnostics")
	}
}

func waitProtocol(t *testing.T, log *protocolLog, marker string) {
	t.Helper()
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		if log.contains(marker) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("OpenVPN protocol marker missing: %s; observed categories: %v (raw log withheld)", marker, log.categories())
}

func startProtocolProcess(t *testing.T, binary string, args ...string) *protocolLog {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	log := &protocolLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal("cannot start test OpenVPN")
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	return log
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("cannot write private test fixture")
	}
}

func testVPNCertificate(t *testing.T, dir string) []byte {
	t.Helper()
	return testVPNCertificateFor(t, dir, time.Hour)
}

func testVPNCertificateFor(t *testing.T, dir string, validFor time.Duration) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "SupiVPN ephemeral test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(validFor),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeTestFile(t, filepath.Join(dir, "ca.pem"), ca)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, cert, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "crt.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	der, err = x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return ca
}

func TestOpenVPNTLSCryptV2(t *testing.T) {
	binary := os.Getenv("SUPIVPN_TEST_OPENVPN")
	linuxClient := os.Getenv("SUPIVPN_TEST_OPENVPN3")
	if binary == "" {
		t.Skip("requires isolated Linux container with OpenVPN 2.7.8 and /dev/net/tun")
	}
	agentBinary := os.Getenv("SUPIVPN_TEST_AGENT")
	if agentBinary == "" {
		t.Fatal("SUPIVPN_TEST_AGENT is required for the real learn-address hook")
	}
	// Generate the synthetic IdP before starting client handshake timers. The
	// immutable signer and metadata are shared; each case gets a fresh agent.
	signer, metadata := testIdP(t)
	for _, tc := range []struct {
		name    string
		groups  []string
		address string
	}{
		{"missing-key", nil, ""},
		{"wrong-key", nil, ""},
		{"dev", []string{devGroup}, "10.203.0.65"},
		{"both", []string{devGroup, coreGroup}, "10.203.0.2"},
		{"core", []string{coreGroup}, "10.203.0.2"},
		{"expanded-core", []string{devGroup, coreGroup}, "10.203.0.129"},
		{"no-group", []string{unrelatedGroup}, ""},
		{"go-core", []string{coreGroup}, "10.203.0.2"},
		{"go-delayed-auth", []string{coreGroup}, "10.203.0.2"},
		{"go-no-group", []string{unrelatedGroup}, ""},
		{"go-bound", []string{coreGroup}, "10.203.0.2"},
		{"go-bound-on-legacy", nil, ""},
		{"go-legacy-on-bound", nil, ""},
		{"go-wrong-key", nil, ""},
		{"go-tampered", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if linuxClient != "" && tc.name != "go-core" && tc.name != "go-delayed-auth" && tc.name != "go-no-group" && tc.name != "go-bound" && tc.name != "go-bound-on-legacy" && tc.name != "go-legacy-on-bound" {
				t.Skip("OpenVPN 3 Linux SAML interoperability subset")
			}
			bound := tc.name == "go-bound" || tc.name == "go-bound-on-legacy"
			proof, err := profile.NewCredential()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			issuer := profile.Issuer{OpenVPN: binary}
			key := filepath.Join(dir, "wrapping.key")
			if err := issuer.EnsureServerKey(context.Background(), key); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(key)
			if err := issuer.EnsureServerKey(context.Background(), key); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(key)
			if !bytes.Equal(before, after) {
				t.Fatal("native server key rotated")
			}
			ca := testVPNCertificate(t, dir)
			socket := filepath.Join(dir, "management.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			config := strings.NewReplacer(
				"/etc/supivpn/tls/crt.pem", filepath.Join(dir, "crt.pem"),
				"extra-certs /etc/supivpn/tls/chain.pem", "# test certificate is self-signed",
				"/etc/supivpn/tls/key.pem", filepath.Join(dir, "key.pem"),
				"/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.pem"),
				"/var/lib/supivpn/tls-crypt-v2-server.key", key,
				"/run/supivpn/management.sock", socket,
				"/opt/supivpn/supivpn", agentBinary,
				"verb 2", "verb 3",
			).Replace(openVPNServerTemplate)
			if strings.Contains(tc.name, "bound") {
				mode := "required"
				if tc.name == "go-bound-on-legacy" {
					mode = "legacy"
				}
				config += "\ntls-crypt-v2-verify \"" + agentBinary + " -verify-profile-metadata " + mode + "\"\n"
			}
			serverConfig := filepath.Join(dir, "server.conf")
			writeTestFile(t, serverConfig, []byte(config))
			serverLog := startProtocolProcess(t, binary, "--config", serverConfig)
			listener.(*net.UnixListener).SetDeadline(time.Now().Add(8 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal("OpenVPN did not connect to the management socket")
			}
			m := newManagement(conn)
			t.Cleanup(m.close)
			if err := m.negotiate(); err != nil {
				t.Fatal(err)
			}
			if err := m.command("hold release"); err != nil {
				t.Fatal(err)
			}
			waitProtocol(t, serverLog, "Initialization Sequence Completed")

			template := strings.Replace(openVPNClientTemplate, "remote supivpn.example.test 1194", "remote 127.0.0.1 1194", 1)
			start, end := strings.Index(template, "<ca>"), strings.Index(template, "</ca>")
			if start < 0 || end < start {
				t.Fatal("client CA block missing")
			}
			template = template[:start] + "<ca>\n" + string(ca) + "</ca>" + template[end+len("</ca>"):]
			output := filepath.Join(dir, "client.ovpn")
			if strings.HasSuffix(tc.name, "wrong-key") {
				key = filepath.Join(dir, "foreign.key")
				if err := issuer.EnsureServerKey(context.Background(), key); err != nil {
					t.Fatal(err)
				}
			}
			issue := func(path string) {
				if !strings.HasPrefix(tc.name, "go-") {
					if err := issuer.Issue(context.Background(), key, []byte(template), path); err != nil {
						t.Fatal("native profile issuance failed")
					}
					return
				}
				serverKey, err := os.ReadFile(key)
				if err != nil {
					t.Fatal("test wrapping key unavailable")
				}
				clientKey, err := profile.GenerateClientKey(serverKey, time.Now())
				if bound {
					clientKey, err = profile.GenerateBoundClientKey(serverKey, time.Now())
				}
				if err != nil {
					t.Fatal("Go client key generation failed")
				}
				if tc.name == "go-tampered" {
					block, _ := pem.Decode(clientKey)
					block.Bytes[256] ^= 1
					clientKey = pem.EncodeToMemory(block)
				}
				data, err := profile.Render([]byte(template), clientKey)
				if bound {
					data, err = profile.RenderBound([]byte(template), clientKey, proof)
				}
				if err != nil {
					t.Fatal("Go profile rendering failed")
				}
				writeTestFile(t, path, data)
			}
			issue(output)
			first, _ := os.ReadFile(output)
			second := filepath.Join(dir, "second.ovpn")
			issue(second)
			secondData, _ := os.ReadFile(second)
			if bytes.Equal(first, secondData) {
				t.Fatal("native client keys reused")
			}
			if bytes.Contains(first, before) || bytes.Contains(first, []byte("server key")) {
				t.Fatal("wrapping key leaked into profile")
			}
			if tc.name == "missing-key" {
				start, end := bytes.Index(first, []byte("<tls-crypt-v2>")), bytes.Index(first, []byte("</tls-crypt-v2>"))
				writeTestFile(t, output, append(first[:start], first[end+len("</tls-crypt-v2>"):]...))
			}
			// The Community CLI needs auth-user-pass to omit a client cert;
			// Connect uses CLIENT_CERT=0. These synthetic values grant no access:
			// only the signed SAML assertion below may authorize the connection.
			authFile := filepath.Join(dir, "cli-test-auth")
			credentials := "unused-test\nunused-test\n"
			if bound {
				credentials = proof.ID + "\n" + proof.Secret + "\n"
			}
			writeTestFile(t, authFile, []byte(credentials))
			invalidKey := tc.name == "missing-key" || strings.HasSuffix(tc.name, "wrong-key") || tc.name == "go-tampered" || tc.name == "go-bound-on-legacy" || tc.name == "go-legacy-on-bound"
			clientArgs := []string{"--config", output,
				"--auth-user-pass", authFile,
				"--dev", "supivpnc", "--dev-type", "tun", "--disable-dco",
				"--ifconfig-noexec", "--route-noexec", "--setenv", "IV_SSO", "webauth",
				"--tls-exit", "--verb", "3"}
			if invalidKey {
				// Only silent key rejection needs an accelerated timeout. Valid
				// clients retain the profile's handshake window: OpenVPN also
				// uses it to detect server silence during AUTH_PENDING.
				clientArgs = append(clientArgs, "--hand-window", "5")
			}
			clientBinary := binary
			if linuxClient != "" {
				// Embedded credentials are the proposed opaque profile proof,
				// not the SAML user's name or password. Authorization below still
				// requires a signed assertion and an allowed group.
				if !bound {
					writeTestFile(t, output, append(first, []byte("\n<auth-user-pass>\nsynthetic-profile-id\nsynthetic-profile-secret\n</auth-user-pass>\n")...))
				}
				clientBinary = linuxClient
				clientArgs = []string{"session-start", "--config", output, "--timeout", "30", "--dco", "false"}
				t.Cleanup(func() {
					cmd := exec.Command(linuxClient, "session-manage", "--config", output, "--disconnect")
					cmd.Stdout, cmd.Stderr = &protocolLog{}, &protocolLog{}
					_ = cmd.Run()
				})
			}
			clientLog := startProtocolProcess(t, clientBinary, clientArgs...)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("client protocol categories: %v (raw log withheld)", clientLog.categories())
					t.Logf("server protocol categories: %v (raw log withheld)", serverLog.categories())
				}
			})
			if invalidKey {
				if linuxClient == "" {
					waitProtocol(t, clientLog, "TLS Error: TLS key negotiation failed")
				} else {
					// Server-side proof of metadata rejection, without waiting
					// for the Linux service's longer reconnect backoff.
					waitProtocol(t, serverLog, "TLS CRYPT V2 VERIFY SCRIPT ERROR")
					time.Sleep(time.Second)
				}
				select {
				case <-m.events:
					t.Fatal("invalid key reached the management authentication interface")
				default:
				}
				if clientLog.contains("WEB_AUTH") || clientLog.contains("VERIFY OK") ||
					serverLog.contains("Peer Connection Initiated") {
					t.Fatal("invalid key exposed TLS or SAML")
				}
				return
			}
			if linuxClient == "" {
				waitProtocol(t, clientLog, "Peer Connection Initiated")
			}
			var e clientEvent
			select {
			case e = <-m.events:
			case <-time.After(10 * time.Second):
				t.Fatal("valid key did not reach authentication")
			}
			if e.kind != "CONNECT" || !supportsWebAuth(e.sso) {
				t.Fatal("missing webauth CONNECT")
			}
			if bound && e.proof != proof {
				t.Fatal("opaque inline proof was not delivered on the authenticated CID/KID")
			}
			if linuxClient != "" && bound && (e.client.deviceID == "" || e.client.deviceIDSource != "IV_HWADDR") {
				t.Fatal("Linux device diagnostic missing")
			}
			a, _ := testApp(t, metadata)
			audit := captureAudit(t, a.agent)
			a.management.close() // Replace the mock socket with the real daemon.
			enableTestGroups(a)
			if tc.name == "expanded-core" {
				a.config = expandedGroupConfig()
				a.pools = newPoolAllocator(a.config)
				if _, err := a.pools.acquire(999, coreGroup); err != nil {
					t.Fatal(err)
				}
			}
			a.connections, a.tickets = map[uint64]*connection{}, map[string]*connection{}
			a.attach(m)
			a.handleEvent(e)
			if linuxClient == "" {
				waitProtocol(t, clientLog, "WEB_AUTH:external:")
			} else {
				waitProtocol(t, clientLog, a.origin.String()+"/login/")
			}
			if tc.name == "go-delayed-auth" {
				// Cross a PUSH_REQUEST retry interval while browser authentication
				// is pending. A five-second client handshake window is too short.
				time.Sleep(7 * time.Second)
				if clientLog.contains("PUSH_REPLY") || clientLog.contains("Initialization Sequence Completed") {
					t.Fatal("pending SAML authentication established a tunnel")
				}
			}
			c := a.connections[e.cid]
			if c == nil {
				t.Fatal("missing pending login")
			}
			handler := a.handler()
			login := confirmVPNLogin(t, handler, a.origin, c.ticket)
			if login.Code != http.StatusFound || len(login.Result().Cookies()) != 2 {
				t.Fatalf("browser SAML login failed: status=%d cookies=%d ready=%v pending=%v", login.Code, len(login.Result().Cookies()), a.Ready(context.Background()), a.now().Before(c.expires))
			}
			assertion := groupAssertionFor(a, tc.groups...)
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = c.requestID
			response := saml.Response{ID: "native-response", InResponseTo: c.requestID,
				Version: "2.0", IssueInstant: time.Now().UTC(), Destination: a.sp.AcsURL.String(),
				Issuer: &saml.Issuer{Value: "https://idp.example.test"},
				Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
			signing, err := saml.GetSigningContext(signer)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signing.SignEnveloped(response.Element())
			if err != nil {
				t.Fatal(err)
			}
			doc := etree.NewDocument()
			doc.SetRoot(signed)
			data, err := doc.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			body := url.Values{"RelayState": {c.ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString(data)}}.Encode()
			request := httptest.NewRequest("POST", a.sp.AcsURL.String(), strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(samlLoginCookie(t, login.Result(), c.ticket))
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, request)
			if tc.address == "" {
				if result.Code != http.StatusForbidden || c.active {
					t.Fatal("SAML group denial bypassed")
				}
				if linuxClient == "" {
					waitProtocol(t, clientLog, "AUTH_FAILED")
				} else {
					select {
					case event := <-m.events:
						if event.kind != "DISCONNECT" {
							t.Fatal("denied Linux client established a tunnel")
						}
					case <-time.After(15 * time.Second):
						t.Fatal("denied Linux client did not disconnect")
					}
				}
				return
			}
			if result.Code != http.StatusOK || c.address.String() != tc.address {
				t.Fatal("SAML did not authorize expected group address")
			}
			if linuxClient == "" {
				waitProtocol(t, clientLog, "ifconfig "+tc.address+" 255.255.255.0")
				waitProtocol(t, clientLog, "Initialization Sequence Completed")
			}
			if clientLog.contains("SIGUSR1") || clientLog.contains("process restarting") {
				t.Fatal("valid-key authentication restarted the client")
			}
			select {
			case established := <-m.events:
				if established.kind != "ESTABLISHED" || established.cid != e.cid {
					t.Fatal("unexpected established event")
				}
				if !established.peer.IsValid() || !established.peer.Addr().IsLoopback() || established.peer.Port() == 0 {
					t.Fatal("native ESTABLISHED did not retain the observed peer endpoint")
				}
				a.handleEvent(established)
				assertPeerAudit(t, audit, "vpn.tunnel_established", e.cid, established.peer.Addr().String(), established.peer.Port())
				row := auditRow(t, audit, "vpn.tunnel_established", e.cid)
				if row["client_version"] != e.client.version || row["client_platform"] != "linux" || row["establishment_ms"] == nil {
					t.Fatal("native establishment audit missing client diagnostics or timing")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("tunnel establishment unconfirmed")
			}
			// Management version 5 and disconnect command must work on 2.7.8.
			if err := m.command(fmt.Sprintf("client-kill %d", e.cid)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
