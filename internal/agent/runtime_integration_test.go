// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/beevik/etree"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controlruntime"
	"supivpn/internal/gateway"
	"supivpn/internal/postgres"
	"supivpn/internal/saml"
	"supivpn/internal/vm"
)

type testVMController struct {
	browser, agent *http.Client
	endpoint       string
	stop           func()
}

func serveRuntimeVM(t *testing.T, app *controlruntime.Application) *testVMController {
	t.Helper()
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	client := seed.Client()
	secure := seed.TLS.Clone()
	seed.Close()
	web, err := tls.Listen("tcp", "127.0.0.1:0", secure)
	if err != nil {
		t.Fatal("test HTTPS listener failed")
	}
	dir, err := os.MkdirTemp("", "supivpn-run-")
	if err != nil {
		web.Close()
		t.Fatal("test directory failed")
	}
	socket := filepath.Join(dir, "agent.sock")
	local, err := vm.ListenAgent(socket, uint32(os.Geteuid()), "runtime-node")
	if err != nil {
		web.Close()
		os.RemoveAll(dir)
		t.Fatal("test Unix listener failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- vm.ServeListeners(ctx, web, local, app.Public, app.Agents) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	stopped := false
	result := &testVMController{browser: client, agent: &http.Client{Transport: transport, Timeout: 5 * time.Second}, endpoint: "https://" + web.Addr().String()}
	result.stop = func() {
		if stopped {
			return
		}
		stopped = true
		client.CloseIdleConnections()
		transport.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("controller shutdown failed")
			}
		case <-time.After(7 * time.Second):
			t.Error("controller shutdown timed out")
		}
		os.RemoveAll(dir)
	}
	t.Cleanup(result.stop)
	return result
}
func runtimeEvent(origin *url.URL, method, path, body string, cookie *http.Cookie) events.APIGatewayV2HTTPRequest {
	route := method + " " + path
	if strings.HasPrefix(path, "/login/") {
		route = "GET /login/{ticket}"
	}
	e := events.APIGatewayV2HTTPRequest{Version: "2.0", RouteKey: route, RawPath: path, Headers: map[string]string{"host": origin.Host, "content-type": "application/x-www-form-urlencoded"},
		Body: base64.StdEncoding.EncodeToString([]byte(body)), IsBase64Encoded: true,
		RequestContext: events.APIGatewayV2HTTPRequestContext{APIID: "testapi", AccountID: "123456789012", Stage: "$default", DomainName: origin.Hostname(), RouteKey: route,
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: method, Path: path}}}
	if cookie != nil {
		e.Cookies = []string{cookie.Name + "=" + cookie.Value}
	}
	return e
}
func runtimeAgentRequest(t *testing.T, client *http.Client, path, body string) (int, []byte) {
	t.Helper()
	r, _ := http.NewRequest("POST", "http://controller/agent/v1/"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal("agent transport failed")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("agent response failed")
	}
	return resp.StatusCode, b
}
func TestRuntimeSAMLAcrossVMAndLambda(t *testing.T) {
	testRuntimeSAML(t, false, "")
}

func TestRuntimeSAMLAcrossVMAndREST(t *testing.T) {
	testRuntimeSAML(t, true, "/supivpn")
}

func testRuntimeSAML(t *testing.T, rest bool, prefix string) {
	p, _ := integrationDatabase(t)
	ctx := context.Background()
	if _, err := p.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal("cannot reset disposable database")
	}
	signer, md := testIdP(t)
	fixture, _ := testApp(t, md)
	fixture.origin.Path = prefix
	fixture.sp.EntityID = fixture.origin.String() + "/saml/metadata"
	fixture.sp.AcsURL = *fixture.origin.JoinPath("saml/acs")
	fixture.sp.MetadataURL = *fixture.origin.JoinPath("saml/metadata")
	metadata, err := xml.Marshal(md)
	if err != nil {
		t.Fatal("cannot render public test metadata")
	}
	metadataPath := filepath.Join(t.TempDir(), "idp-metadata.xml")
	if err = os.WriteFile(metadataPath, metadata, 0600); err != nil {
		t.Fatal("cannot write public metadata fixture")
	}
	cfg := controlruntime.Config{PublicURL: fixture.origin.String(), IDPMetadata: metadataPath, SAMLGroupsAttribute: "groups",
		Groups: []controlruntime.Group{{Name: "admins-vpn", Priority: 10}, {Name: "engineers-production-vpn", Priority: 20}}, PendingSeconds: 180, SessionSeconds: 900}
	open := func() *controlruntime.Application {
		a, e := controlruntime.Open(ctx, cfg, os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
		if e != nil {
			t.Fatal("controller runtime initialization failed")
		}
		t.Cleanup(a.Close)
		return a
	}
	lambdaApp := open()
	adapter, err := gateway.New(gateway.Config{APIID: "testapi", AccountID: "123456789012", Stage: "$default", Domains: []string{fixture.origin.Hostname()}}, lambdaApp.Origin, lambdaApp.Public, lambdaApp.Agents)
	if err != nil {
		t.Fatal("gateway initialization failed")
	}
	handle := func(ctx context.Context, e events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		if !rest {
			return adapter.Handle(ctx, e)
		}
		resource := strings.TrimPrefix(e.RouteKey, e.RequestContext.HTTP.Method+" ")
		e.RawPath = prefix + e.RawPath
		r := events.APIGatewayProxyRequest{Resource: prefix + resource, Path: e.RawPath, HTTPMethod: e.RequestContext.HTTP.Method,
			Headers: e.Headers, Body: e.Body, IsBase64Encoded: e.IsBase64Encoded,
			MultiValueHeaders: map[string][]string{"Cookie": e.Cookies},
			RequestContext: events.APIGatewayProxyRequestContext{APIID: "testapi", AccountID: "123456789012", Stage: "$default",
				DomainName: fixture.origin.Hostname(), ResourcePath: prefix + resource, Path: "/$default" + e.RawPath, HTTPMethod: e.RequestContext.HTTP.Method}}
		if len(e.Cookies) == 0 {
			delete(r.MultiValueHeaders, "Cookie")
		}
		out, err := adapter.HandleREST(ctx, r)
		return events.APIGatewayV2HTTPResponse{StatusCode: out.StatusCode, Headers: out.Headers, Cookies: out.MultiValueHeaders["Set-Cookie"], Body: out.Body}, err
	}
	for _, tc := range []struct {
		name     string
		groups   []string
		expected string
		reverse  bool
	}{
		{"vm-start-lambda-callback", []string{"engineers-production-vpn", "admins-vpn"}, "admins-vpn", false},
		{"lambda-start-vm-callback", []string{"engineers-production-vpn"}, "engineers-production-vpn", true},
		{"no-vpn-group", []string{"unrelated-group"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err = p.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
				t.Fatal("cannot reset disposable database")
			}
			app := open()
			server := serveRuntimeVM(t, app)
			if status, _ := runtimeAgentRequest(t, server.agent, "rotate", `{"generation":"g1"}`); status != 204 {
				t.Fatalf("node registration: %d", status)
			}
			// Exercise the real agent HTTP client and management bridge, including
			// after the controller is replaced below. Unix peer auth is the VM
			// alternative to the separately tested EC2 SigV4 transport.
			client, err := agentclient.New("https://controller.test", agentRoundTrip(func(r *http.Request) (*http.Response, error) {
				copy := r.Clone(r.Context())
				copy.URL.Scheme, copy.URL.Host = "http", "controller"
				return server.agent.Transport.RoundTrip(copy)
			}), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			node, commands := remoteFixture(t, client)
			connectRemote(t, node, commands)
			ticket := node.connections[7].ticket
			var cookie *http.Cookie
			if tc.reverse {
				out, e := handle(ctx, runtimeEvent(fixture.origin, "GET", "/login/"+ticket, "", nil))
				if e != nil || out.StatusCode != 302 || len(out.Cookies) != 1 {
					t.Fatal("Lambda did not start SAML")
				}
				cookie, err = http.ParseSetCookie(out.Cookies[0])
				if err != nil {
					t.Fatal("invalid Lambda cookie")
				}
			} else {
				req, _ := http.NewRequest("GET", server.endpoint+prefix+"/login/"+ticket, nil)
				req.Host = fixture.origin.Host
				resp, e := server.browser.Do(req)
				if e != nil {
					t.Fatal("VM did not start SAML")
				}
				resp.Body.Close()
				if resp.StatusCode != 302 || len(resp.Cookies()) != 1 {
					t.Fatalf("VM start status: %d", resp.StatusCode)
				}
				cookie = resp.Cookies()[0]
			}
			pending, err := postgres.New(p).Lookup(ctx, ticket, sha256.Sum256([]byte(cookie.Value)))
			if err != nil {
				t.Fatal("browser binding not shared")
			}
			assertion := assertionFor(fixture)
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
			values := []saml.AttributeValue{}
			for _, name := range tc.groups {
				values = append(values, saml.AttributeValue{Value: name})
			}
			assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: []saml.Attribute{{Name: "groups", Values: values}}}}
			sr := saml.Response{ID: "response-runtime", InResponseTo: pending.RequestID, Version: "2.0", IssueInstant: time.Now().UTC(), Destination: fixture.sp.AcsURL.String(), Issuer: &assertion.Issuer,
				Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
			signing, e := saml.GetSigningContext(signer)
			if e != nil {
				t.Fatal("signer unavailable")
			}
			signed, e := signing.SignEnveloped(sr.Element())
			if e != nil {
				t.Fatal("cannot sign SAML fixture")
			}
			doc := etree.NewDocument()
			doc.SetRoot(signed)
			signedXML, e := doc.WriteToString()
			if e != nil {
				t.Fatal("fixture render failed")
			}
			body := url.Values{"RelayState": {ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(signedXML))}}.Encode()
			// Destroy the VM controller and its pool after redirect. The agent ticket
			// and browser binding must survive in PostgreSQL without extending TTL.
			server.stop()
			app.Close()
			app = open()
			server = serveRuntimeVM(t, app)
			if tc.reverse {
				req, _ := http.NewRequest("POST", server.endpoint+prefix+"/saml/acs", strings.NewReader(body))
				req.Host = fixture.origin.Host
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(cookie)
				resp, e := server.browser.Do(req)
				if e != nil {
					t.Fatal("VM callback failed")
				}
				resp.Body.Close()
				if resp.StatusCode != 202 {
					t.Fatalf("VM callback status: %d", resp.StatusCode)
				}
			} else {
				out, e := handle(ctx, runtimeEvent(fixture.origin, "POST", "/saml/acs", body, cookie))
				want := http.StatusAccepted
				if tc.expected == "" {
					want = http.StatusForbidden
				}
				if e != nil || out.StatusCode != want || (want == http.StatusAccepted && len(out.Cookies) != 1) {
					t.Fatalf("Lambda callback status: %d", out.StatusCode)
				}
			}
			out, e := handle(ctx, runtimeEvent(fixture.origin, "POST", "/saml/acs", body, cookie))
			if e != nil || out.StatusCode != 410 {
				t.Fatal("callback replay accepted across runtimes")
			}
			poll := `{"generation":"g1","cid":7,"kid":2}`
			status, b := runtimeAgentRequest(t, server.agent, "fetch", poll)
			var decision agentapi.Decision
			if status != 200 || json.Unmarshal(b, &decision) != nil || decision.NodeID != "runtime-node" || decision.Generation != "g1" || decision.CID != 7 || decision.KID != 2 || decision.GroupName != tc.expected {
				t.Fatalf("decision binding lost: status=%d", status)
			}
			if decision.ExpiresAt.After(pending.ExpiresAt) {
				t.Fatal("restart extended pending deadline")
			}
			if (tc.expected == "") != (decision.DenialReason != "") {
				t.Fatal("group refusal lost")
			}
			remoteStepNow(node)
			command := <-commands
			if tc.expected == "" {
				if !strings.HasPrefix(command, "client-deny 7 2 ") || node.connections[7].active {
					t.Fatal("denied SAML created a tunnel")
				}
			} else {
				address := "10.203.0.2"
				if tc.expected == "engineers-production-vpn" {
					address = "10.203.0.65"
				}
				if command != "client-auth 7 2\nifconfig-push "+address+" 255.255.255.0\nEND" ||
					!node.connections[7].active {
					t.Fatal("remote SAML did not apply the expected group IP")
				}
			}
			remoteStepNow(node) // Record the real OpenVPN management result.
			if len(node.remote.jobs) != 0 {
				t.Fatal("agent did not acknowledge decision")
			}
			outcome := "applied"
			if tc.expected == "" {
				outcome = "denied"
			}
			ack, _ := json.Marshal(map[string]string{"generation": "g1", "decision_id": decision.ID, "outcome": outcome})
			for i := 0; i < 2; i++ {
				if status, _ = runtimeAgentRequest(t, server.agent, "ack", string(ack)); status != 204 {
					t.Fatalf("ACK retry failed: %d", status)
				}
			}
			if status, _ = runtimeAgentRequest(t, server.agent, "fetch", poll); status != 204 {
				t.Fatal("acknowledged decision redelivered")
			}
		})
	}
}
