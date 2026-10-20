// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentJSONAmbiguity(t *testing.T) {
	for name, body := range map[string]string{
		"escaped-duplicate": `{"generation":"g1","\u0067eneration":"g2","cid":0,"kid":2}`,
		"case-alias": `{"Generation":"g1","cid":0,"kid":2}`,
		"mixed-case-duplicate": `{"generation":"g1","GENERATION":"g2","cid":0,"kid":2}`,
		"fractional-id": `{"generation":"g1","cid":0.0,"kid":2}`,
		"exponent-id": `{"generation":"g1","cid":1e0,"kid":2}`,
		"overflow-id": `{"generation":"g1","cid":9223372036854775808,"kid":2}`,
		"string-id": `{"generation":"g1","cid":"0","kid":2}`,
		"unicode-digit": `{"generation":"g1","cid":０,"kid":2}`,
		"generation-command": `{"generation":"g1\nclient-auth-nt 7 2","cid":0,"kid":2}`,
		"nul-generation": `{"generation":"g1\u0000","cid":0,"kid":2}`,
		"escaped-node-spoof": `{"generation":"g1","cid":0,"kid":2,"\u006eode_id":"node-b"}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := &recordedStore{}
			handler := New(s, time.Minute)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, requestFor("/agent/v1/fetch", body, "node-a"))
			if w.Code != 400 || s.calls != 0 || w.Body.String() != `{"error":"request refused"}` {
				t.Fatal("ambiguous input reached the store or escaped the generic error response")
			}
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, requestFor("/agent/v1/rotate", `{"generation":"g1"}`, "node-a"))
			if w.Code != 204 || s.calls != 1 || s.actor.NodeID != "node-a" {
				t.Fatal("bad request poisoned a later valid request")
			}
		})
	}
}

func TestSecurityAllAgentOperationsRequireTransportIdentity(t *testing.T) {
	for operation, body := range map[string]string{
		"rotate": `{"generation":"g1"}`,
		"heartbeat": `{"generation":"g1"}`,
		"register": `{"generation":"g1","cid":0,"kid":2,"ticket":"` + strings.Repeat("a", 43) + `"}`,
		"fetch": `{"generation":"g1","cid":0,"kid":2}`,
		"ack": `{"generation":"g1","decision_id":"d1","outcome":"applied"}`,
		"cancel": `{"generation":"g1","cid":0,"kid":2}`,
	} {
		t.Run(operation, func(t *testing.T) {
			s := &recordedStore{}
			handler := New(s, time.Minute)
			for _, identity := range []string{"", "node-a"} {
				r := requestFor("/agent/v1/"+operation, body, identity)
				r.Header.Set("X-Node-ID", "node-b")
				r.Header.Set("Authorization", "Bearer node-b")
				r.Header.Set("X-Forwarded-User", "node-b")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if identity == "" {
					if w.Code != 403 || s.calls != 0 {
						t.Fatal("headers authorized an unauthenticated operation")
					}
				} else if w.Code >= 400 || s.calls != 1 || s.actor.NodeID != "node-a" {
					t.Fatal("headers replaced the authenticated transport identity")
				}
			}
		})
	}
}
