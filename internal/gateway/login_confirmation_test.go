// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestLoginConfirmationGatewayRoutes(t *testing.T) {
	for _, prefix := range []string{"", "/supivpn"} {
		t.Run(prefix, func(t *testing.T) {
			calls := 0
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method == http.MethodPost {
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "consent=synthetic" ||
						r.Header.Get("Origin") != "https://vpn.example.test" || len(r.Cookies()) != 1 {
						t.Error("gateway changed confirmation binding")
					}
				}
				w.WriteHeader(http.StatusNoContent)
			})
			origin, _ := url.Parse("https://vpn.example.test" + prefix)
			a, err := NewPublic(configForTest(), origin, h)
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				path := prefix + "/login/test-ticket"
				route := method + " " + prefix + "/login/{ticket}"
				e := eventFor(method, path)
				e.RouteKey, e.RequestContext.RouteKey = route, route
				e.Headers["origin"] = "https://vpn.example.test"
				e.Headers["content-type"] = "application/x-www-form-urlencoded"
				e.Cookies = []string{"consent=synthetic"}
				e.Body = "consent=synthetic"
				before := calls
				out, err := a.Handle(context.Background(), e)
				if err != nil || out.StatusCode != http.StatusNoContent || calls != before+1 {
					t.Fatal("HTTP v2 login route unavailable")
				}
				rest := restEvent(method, path)
				rest.Resource, rest.RequestContext.ResourcePath = prefix+"/login/{ticket}", prefix+"/login/{ticket}"
				rest.Headers["Origin"] = "https://vpn.example.test"
				rest.Headers["Content-Type"] = "application/x-www-form-urlencoded"
				rest.Headers["Cookie"] = "consent=synthetic"
				rest.Body = "consent=synthetic"
				before = calls
				response, err := a.HandleREST(context.Background(), rest)
				if err != nil || response.StatusCode != http.StatusNoContent || calls != before+1 {
					t.Fatal("REST login route unavailable")
				}
				for name, mutate := range map[string]func(*events.APIGatewayV2HTTPRequest){
					"wrong-route": func(e *events.APIGatewayV2HTTPRequest) {
						e.RouteKey, e.RequestContext.RouteKey = "ANY /{proxy+}", "ANY /{proxy+}"
					},
					"encoded-ticket": func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = prefix + "/login/%74est-ticket" },
					"extra-segment": func(e *events.APIGatewayV2HTTPRequest) {
						e.RawPath += "/extra"
						e.RequestContext.HTTP.Path = e.RawPath
					},
					"empty-ticket": func(e *events.APIGatewayV2HTTPRequest) {
						e.RawPath, e.RequestContext.HTTP.Path = prefix+"/login/", prefix+"/login/"
					},
					"wrong-method": func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.HTTP.Method = http.MethodDelete },
				} {
					t.Run(method+"/"+name, func(t *testing.T) {
						attack := e
						mutate(&attack)
						before := calls
						response, err := a.Handle(context.Background(), attack)
						if err != nil || response.StatusCode < 400 || calls != before {
							t.Fatal("ambiguous login route reached controller")
						}
					})
				}
			}
		})
	}
}
