// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"supivpn/internal/metrics"
)

func TestMetricsGatewayIsolation(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest, err := metrics.TokenDigest([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	endpoint := metrics.Protect(digest, metrics.Handler(func(context.Context) ([]metrics.Family, error) { calls++; return nil, nil }))
	origin, _ := url.Parse("https://vpn.example.test")
	public, err := NewPublic(configForTest(), origin, metrics.PublicRoute("", http.NotFoundHandler(), endpoint))
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*events.APIGatewayV2HTTPRequest){
		func(e *events.APIGatewayV2HTTPRequest) { delete(e.Headers, "authorization") },
		func(e *events.APIGatewayV2HTTPRequest) { e.Headers["authorization"] += ",Bearer another" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RawQueryString = "token=not-accepted" },
		func(e *events.APIGatewayV2HTTPRequest) { e.Body = "not-accepted" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/%6detrics" },
		func(e *events.APIGatewayV2HTTPRequest) {
			e.RouteKey = "GET /{proxy+}"
			e.RequestContext.RouteKey = e.RouteKey
		},
		func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.APIID = "wrong" },
	} {
		e := eventFor("GET", "/metrics")
		e.Headers["authorization"] = "Bearer " + token
		edit(&e)
		out, _ := public.Handle(context.Background(), e)
		if out.StatusCode < 400 || calls != 0 {
			t.Fatal("unsafe metrics request accepted")
		}
	}
	e := eventFor("GET", "/metrics")
	e.Headers["authorization"] = "Bearer " + token
	out, _ := public.Handle(context.Background(), e)
	if out.StatusCode != 200 || calls != 1 {
		t.Fatal("valid HTTP v2 scrape refused")
	}
	re := restEvent("GET", "/metrics")
	re.Headers["Authorization"] = "Bearer " + token
	rest, _ := public.HandleREST(context.Background(), re)
	if rest.StatusCode != 200 || calls != 2 {
		t.Fatal("valid REST scrape refused")
	}
	re.MultiValueHeaders = map[string][]string{"Host": {"vpn.example.test"}, "Authorization": {"Bearer " + token, "Bearer " + token}}
	rest, _ = public.HandleREST(context.Background(), re)
	if rest.StatusCode < 400 || calls != 2 {
		t.Fatal("duplicate REST credentials accepted")
	}
	agent, err := NewAgent(configForTest(), origin, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("metrics reached IAM agent handler") }))
	if err != nil {
		t.Fatal(err)
	}
	out, _ = agent.Handle(context.Background(), e)
	if out.StatusCode < 400 {
		t.Fatal("agent Lambda exposes metrics")
	}
	disabled, _ := NewPublic(configForTest(), origin, metrics.PublicRoute("", http.NotFoundHandler(), nil))
	out, _ = disabled.Handle(context.Background(), e)
	if out.StatusCode != 404 {
		t.Fatal("disabled Lambda metrics exposed")
	}
	origin.Path = "/supivpn"
	prefixed, _ := NewPublic(configForTest(), origin, metrics.PublicRoute(origin.Path, http.NotFoundHandler(), endpoint))
	e = eventFor("GET", "/supivpn/metrics")
	e.Headers["authorization"] = "Bearer " + token
	out, _ = prefixed.Handle(context.Background(), e)
	if out.StatusCode != 200 {
		t.Fatal("prefixed metrics route refused")
	}
}
