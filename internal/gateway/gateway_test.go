// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/postgres"
	"github.com/aws/aws-lambda-go/events"
)

const testPrincipal = "arn:aws:sts::123456789012:assumed-role/supivpn-agent/i-0123456789abcdef0"

func (s *nodeRecorder) Heartbeat(_ context.Context, a postgres.Agent) error { s.node = a.NodeID; return nil }

func configForTest() Config {
	return Config{APIID: "testapi", AccountID: "123456789012", Stage: "$default", Domains: []string{"vpn.example.test", "testapi.execute-api.eu-central-1.amazonaws.com"}, AgentPrincipals: map[string]string{testPrincipal: "node-a"}}
}
func eventFor(method, path string) events.APIGatewayV2HTTPRequest {
	route := method + " " + path
	return events.APIGatewayV2HTTPRequest{Version: "2.0", RouteKey: route, RawPath: path, Headers: map[string]string{"host": "vpn.example.test"},
		RequestContext: events.APIGatewayV2HTTPRequestContext{APIID: "testapi", AccountID: "123456789012", Stage: "$default", DomainName: "vpn.example.test", RouteKey: route,
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: method, Path: path}}}
}
func iamEvent() events.APIGatewayV2HTTPRequest {
	e := eventFor("POST", "/agent/v1/rotate")
	e.Body = `{"generation":"g1"}`
	e.Headers["content-type"] = "application/json"
	e.RequestContext.DomainName = "testapi.execute-api.eu-central-1.amazonaws.com"
	e.Headers["host"] = e.RequestContext.DomainName
	e.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
		IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{AccountID: "123456789012", UserARN: testPrincipal}}
	return e
}
func adapterFor(t *testing.T, public, agents http.Handler) *Adapter {
	t.Helper()
	origin, _ := url.Parse("https://vpn.example.test")
	a, err := New(configForTest(), origin, public, agents)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestGatewayPublicRoundTrip(t *testing.T) {
	var received string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Host != "vpn.example.test" || r.URL.Scheme != "https" {
			t.Error("canonical HTTPS origin missing")
		}
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		cookies := r.Cookies()
		if len(cookies) != 2 || cookies[0].Value != "binding" || cookies[1].Value != "value" {
			t.Error("API Gateway cookie fields lost")
		}
		http.SetCookie(w, &http.Cookie{Name: "one", Value: "a", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})
		http.SetCookie(w, &http.Cookie{Name: "two", Value: "b", Secure: true})
		w.WriteHeader(202)
		w.Write(append([]byte("queued"), 0))
	})
	a := adapterFor(t, h, http.NotFoundHandler())
	e := eventFor("POST", "/saml/acs")
	e.Headers["content-type"] = "application/x-www-form-urlencoded"
	e.Headers["x-forwarded-proto"] = "http"
	e.Headers["cookie"] = "forged=ignored"
	e.Cookies = []string{"browser=binding", "other=value"}
	body := "SAMLResponse=abc%2B%2F%3D&RelayState=ticket"
	e.Body = base64.StdEncoding.EncodeToString([]byte(body))
	e.IsBase64Encoded = true
	out, err := a.Handle(context.Background(), e)
	decoded, _ := base64.StdEncoding.DecodeString(out.Body)
	if err != nil || out.StatusCode != 202 || received != body || len(out.Cookies) != 2 || string(decoded) != string(append([]byte("queued"), 0)) || !out.IsBase64Encoded {
		t.Fatal("HTTP v2 conversion changed SAML request/response")
	}
}
func TestGatewayRejectsUntrustedEnvelope(t *testing.T) {
	cases := []struct {
		name string
		edit func(*events.APIGatewayV2HTTPRequest)
	}{
		{"wrong-version", func(e *events.APIGatewayV2HTTPRequest) { e.Version = "1.0" }},
		{"wrong-api", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.APIID = "other" }},
		{"wrong-account", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.AccountID = "000000000000" }},
		{"wrong-stage", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.Stage = "other" }},
		{"wrong-domain", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.DomainName = "evil.example" }},
		{"public-default-domain", func(e *events.APIGatewayV2HTTPRequest) {
			e.RequestContext.DomainName = "testapi.execute-api.eu-central-1.amazonaws.com"
		}},
		{"wrong-host", func(e *events.APIGatewayV2HTTPRequest) { e.Headers["host"] = "evil.example" }},
		{"missing-host", func(e *events.APIGatewayV2HTTPRequest) { delete(e.Headers, "host") }},
		{"duplicate-host", func(e *events.APIGatewayV2HTTPRequest) { e.Headers["Host"] = "vpn.example.test" }},
		{"path-mismatch", func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/saml/acs" }},
		{"default-route", func(e *events.APIGatewayV2HTTPRequest) {
			e.RouteKey = "$default"
			e.RequestContext.RouteKey = "$default"
		}},
		{"route-mismatch", func(e *events.APIGatewayV2HTTPRequest) { e.RouteKey = "GET /{proxy+}" }},
		{"bad-base64", func(e *events.APIGatewayV2HTTPRequest) { e.Body = "!"; e.IsBase64Encoded = true }},
		{"body-limit", func(e *events.APIGatewayV2HTTPRequest) { e.Body = strings.Repeat("a", (1<<20)+1) }},
		{"header-injection", func(e *events.APIGatewayV2HTTPRequest) {
			e.Headers["x-injected"] = "value" + string([]byte{13, 10}) + "other:value"
		}},
		{"cookie-injection", func(e *events.APIGatewayV2HTTPRequest) {
			e.Cookies = []string{"a=b" + string([]byte{13, 10}) + "other:value"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ })
			a := adapterFor(t, h, h)
			e := eventFor("GET", "/healthz")
			tc.edit(&e)
			out, err := a.Handle(context.Background(), e)
			if err != nil || out.StatusCode < 400 || calls != 0 {
				t.Fatalf("invalid envelope reached handler: %d", out.StatusCode)
			}
		})
	}
}

type nodeRecorder struct {
	node  string
	calls int
}

func (s *nodeRecorder) RotateNode(_ context.Context, node, prev, next string) error {
	s.node = node
	s.calls++
	return nil
}
func (s *nodeRecorder) Register(context.Context, postgres.Agent, postgres.Connection, string, time.Duration) error {
	panic("unexpected operation")
}
func (s *nodeRecorder) Fetch(context.Context, postgres.Agent, postgres.Connection) (postgres.Decision, error) {
	panic("unexpected operation")
}
func (s *nodeRecorder) Acknowledge(context.Context, postgres.Agent, string, postgres.Outcome) error {
	panic("unexpected operation")
}
func (s *nodeRecorder) Cancel(context.Context, postgres.Agent, postgres.Connection) error {
	panic("unexpected operation")
}

func TestGatewayAgentUsesOnlyIAMContext(t *testing.T) {
	s := &nodeRecorder{}
	a := adapterFor(t, http.NotFoundHandler(), agentapi.New(s, time.Minute))
	e := iamEvent()
	e.Headers["x-node-id"] = "node-b"
	out, err := a.Handle(context.Background(), e)
	if err != nil || out.StatusCode != 204 || s.node != "node-a" {
		t.Fatalf("authenticated agent request failed or trusted header: %d", out.StatusCode)
	}
	for _, tc := range []struct {
		name string
		edit func(*events.APIGatewayV2HTTPRequest)
	}{
		{"missing-authorizer", func(e *events.APIGatewayV2HTTPRequest) {
			e.RequestContext.Authorizer = nil
			e.Headers["authorization"] = testPrincipal
		}},
		{"no-iam", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.Authorizer.IAM = nil }},
		{"wrong-session", func(e *events.APIGatewayV2HTTPRequest) {
			e.RequestContext.Authorizer.IAM.UserARN = strings.Replace(testPrincipal, "i-0123456789abcdef0", "i-0123456789abcdef1", 1)
		}},
		{"wrong-role", func(e *events.APIGatewayV2HTTPRequest) {
			e.RequestContext.Authorizer.IAM.UserARN = strings.Replace(testPrincipal, "supivpn-agent", "other-role", 1)
		}},
		{"iam-account", func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.Authorizer.IAM.AccountID = "000000000000" }},
		{"default-route", func(e *events.APIGatewayV2HTTPRequest) {
			e.RouteKey = "$default"
			e.RequestContext.RouteKey = "$default"
		}},
		{"encoded-route", func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/agent/v1/%72otate" }},
		{"body-node", func(e *events.APIGatewayV2HTTPRequest) { e.Body = `{"generation":"g1","node_id":"node-b"}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := s.calls
			e := iamEvent()
			tc.edit(&e)
			out, _ := a.Handle(context.Background(), e)
			if out.StatusCode < 400 || s.calls != before {
				t.Fatal("invalid node identity reached store")
			}
		})
	}
}
func TestGatewayConfigurationAndResponseLimit(t *testing.T) {
	origin, _ := url.Parse("https://vpn.example.test")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", (2<<20)+1))) })
	c := configForTest()
	a, err := New(c, origin, h, h)
	if err != nil {
		t.Fatal(err)
	}
	c.Domains[0] = "changed"
	c.AgentPrincipals[testPrincipal] = "node-b"
	origin.Host = "changed"
	out, _ := a.Handle(context.Background(), eventFor("GET", "/healthz"))
	if out.StatusCode != 500 {
		t.Fatal("response limit or immutable configuration failed")
	}
	for _, principal := range []string{"*", strings.Replace(testPrincipal, "123456789012", "000000000000", 1), strings.Replace(testPrincipal, "i-0123456789abcdef0", "human-session", 1)} {
		c = configForTest()
		c.AgentPrincipals = map[string]string{principal: "node-a"}
		origin, _ = url.Parse("https://vpn.example.test")
		if _, err = New(c, origin, h, h); err == nil {
			t.Fatal("non-instance principal mapping accepted")
		}
	}
}
