// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"github.com/aws/aws-lambda-go/events"
)

func restEvent(method, path string) events.APIGatewayProxyRequest {
	return events.APIGatewayProxyRequest{
		Resource: path, Path: path, HTTPMethod: method, Headers: map[string]string{"Host": "vpn.example.test"},
		RequestContext: events.APIGatewayProxyRequestContext{
			APIID: "testapi", AccountID: "123456789012", Stage: "$default",
			DomainName: "vpn.example.test", ResourcePath: path, Path: "/$default" + path, HTTPMethod: method,
		},
	}
}
func TestRESTSAMLBodyAndCookies(t *testing.T) {
	body := "SAMLResponse=abc%2B%2F%3D&RelayState=opaque"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != body || len(r.Cookies()) != 2 || r.TLS == nil {
			t.Error("REST changed browser request")
		}
		http.SetCookie(w, &http.Cookie{Name: "first", Value: "one", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})
		http.SetCookie(w, &http.Cookie{Name: "second", Value: "two", Secure: true})
		w.Write([]byte("ready"))
	})
	a := adapterFor(t, h, http.NotFoundHandler())
	e := restEvent("POST", "/saml/acs")
	e.Body = base64.StdEncoding.EncodeToString([]byte(body))
	e.IsBase64Encoded = true
	e.MultiValueHeaders = map[string][]string{"Cookie": {"browser=one", "other=two"}, "Host": {"vpn.example.test"}}
	out, err := a.HandleREST(context.Background(), e)
	if err != nil || out.StatusCode != 200 || out.Body != "ready" || out.IsBase64Encoded || len(out.MultiValueHeaders["Set-Cookie"]) != 2 {
		t.Fatal("REST response changed")
	}
}
func TestRESTIdentityAndRejection(t *testing.T) {
	s := &nodeRecorder{}
	a := adapterFor(t, http.NotFoundHandler(), agentapi.New(s, time.Minute))
	newEvent := func() events.APIGatewayProxyRequest {
		e := restEvent("POST", "/agent/v1/rotate")
		e.Body = `{"generation":"g1"}`
		e.Headers["Content-Type"] = "application/json"
		e.RequestContext.Identity = events.APIGatewayRequestIdentity{AccountID: "123456789012", UserArn: testPrincipal}
		return e
	}
	e := newEvent()
	out, _ := a.HandleREST(context.Background(), e)
	if out.StatusCode != 204 || s.node != "node-a" {
		t.Fatal("REST IAM mapping failed")
	}
	for _, edit := range []func(*events.APIGatewayProxyRequest){
		func(e *events.APIGatewayProxyRequest) {
			e.RequestContext.Identity.UserArn = ""
			e.Headers["Authorization"] = testPrincipal
		},
		func(e *events.APIGatewayProxyRequest) {
			e.RequestContext.Identity.UserArn = strings.Replace(testPrincipal, "abcdef0", "abcdef1", 1)
		},
		func(e *events.APIGatewayProxyRequest) { e.RequestContext.APIID = "other" },
		func(e *events.APIGatewayProxyRequest) { e.Resource = "/{proxy+}" },
		func(e *events.APIGatewayProxyRequest) { e.RequestContext.HTTPMethod = "GET" },
		func(e *events.APIGatewayProxyRequest) { e.RequestContext.Path = "/different" },
		func(e *events.APIGatewayProxyRequest) {
			e.MultiValueHeaders = map[string][]string{"Host": {"vpn.example.test", "evil.test"}}
		},
		func(e *events.APIGatewayProxyRequest) {
			e.MultiValueHeaders = map[string][]string{"Content-Type": {"text/plain"}}
		},
	} {
		e = newEvent()
		edit(&e)
		before := s.calls
		out, _ = a.HandleREST(context.Background(), e)
		if out.StatusCode < 400 || s.calls != before {
			t.Fatal("untrusted REST request reached handler")
		}
	}
}

func TestRESTProfileDownloadRouteAndAttachment(t *testing.T) {
    calls := 0
    body := "client\nremote vpn.example.test 1194\n"
    h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        if r.Method == "GET" {
            http.Redirect(w, r, "https://idp.example.test/login", http.StatusFound)
            return
        }
        w.Header().Set("Content-Type", "application/x-openvpn-profile")
        w.Header().Set("Content-Disposition", "attachment; filename=\"supivpn.ovpn\"")
        w.Header().Set("Cache-Control", "no-store, private")
        w.Write([]byte(body))
    })
    a := adapterFor(t, h, http.NotFoundHandler())
    out, err := a.HandleREST(context.Background(), restEvent("GET", "/profile"))
    if err != nil || out.StatusCode != 302 || calls != 1 { t.Fatal("profile entry route unavailable") }
    out, err = a.HandleREST(context.Background(), restEvent("POST", "/saml/acs"))
    if err != nil || out.StatusCode != 200 || out.Body != body || out.IsBase64Encoded ||
        out.Headers["Content-Disposition"] != "attachment; filename=\"supivpn.ovpn\"" ||
        out.Headers["Cache-Control"] != "no-store, private" { t.Fatal("REST changed profile attachment") }
    for _, event := range []events.APIGatewayProxyRequest{
        restEvent("POST", "/profile"), restEvent("GET", "/profile/extra"),
    } {
        before := calls
        out, _ = a.HandleREST(context.Background(), event)
        if out.StatusCode < 400 || calls != before { t.Fatal("unexpected profile route dispatched") }
    }
}
