// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestGatewayProfileLaunch(t *testing.T) {
	for _, prefix := range []string{"", "/supivpn"} {
		for _, format := range []string{"rest", "http-v2"} {
			t.Run(format+prefix, func(t *testing.T) {
				calls := 0
				body := "SAMLResponse=ignored&RelayState=https://evil.example.test"
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					data, err := io.ReadAll(r.Body)
					if err != nil || string(data) != body || r.TLS == nil || r.Method != "POST" {
						t.Fatal("launch request changed at the gateway")
					}
					w.Header().Set("Location", prefix+"/profile")
					w.Header().Set("Cache-Control", "no-store")
					w.WriteHeader(http.StatusSeeOther)
				})
				origin, _ := url.Parse("https://vpn.example.test" + prefix)
				a, err := New(configForTest(), origin, h, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("public launch reached the agent API")
				}))
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"valid", "get", "other-path", "wrong-host", "agent-host", "wrong-api", "catch-all", "encoded-path", "oversized"} {
					t.Run(name, func(t *testing.T) {
						method, path := "POST", prefix+"/saml/launch"
						if name == "get" {
							method = "GET"
						}
						if name == "other-path" {
							path += "/extra"
						}
						before := calls
						var status int
						var headers map[string]string
						if format == "rest" {
							e := restEvent(method, path)
							e.Body = body
							switch name {
							case "wrong-host":
								e.Headers["Host"] = "evil.example.test"
							case "agent-host":
								e.RequestContext.DomainName = "testapi.execute-api.eu-central-1.amazonaws.com"
							case "wrong-api":
								e.RequestContext.APIID = "other"
							case "catch-all":
								e.Resource = prefix + "/{proxy+}"
								e.RequestContext.ResourcePath = e.Resource
							case "encoded-path":
								e.Path = prefix + "/saml/%6caunch"
								e.RequestContext.Path = "/$default" + e.Path
							case "oversized":
								e.Body = strings.Repeat("x", (1<<20)+1)
							}
							out, err := a.HandleREST(context.Background(), e)
							if err != nil {
								t.Fatal(err)
							}
							status, headers = out.StatusCode, out.Headers
						} else {
							e := eventFor(method, path)
							e.Body = body
							switch name {
							case "wrong-host":
								e.Headers["host"] = "evil.example.test"
							case "agent-host":
								e.RequestContext.DomainName = "testapi.execute-api.eu-central-1.amazonaws.com"
							case "wrong-api":
								e.RequestContext.APIID = "other"
							case "catch-all":
								e.RouteKey = "$default"
								e.RequestContext.RouteKey = "$default"
							case "encoded-path":
								e.RawPath = prefix + "/saml/%6caunch"
							case "oversized":
								e.Body = strings.Repeat("x", (1<<20)+1)
							}
							out, err := a.Handle(context.Background(), e)
							if err != nil {
								t.Fatal(err)
							}
							status, headers = out.StatusCode, out.Headers
						}
						if name == "valid" {
							if status != 303 || calls != before+1 || headers["Location"] != prefix+"/profile" || headers["Cache-Control"] != "no-store" {
								t.Fatal("gateway changed launch redirect")
							}
						} else if status < 400 || calls != before {
							t.Fatal("untrusted launch reached the handler")
						}
					})
				}
			})
		}
	}
}
