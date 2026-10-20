// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"supivpn/internal/postgres"
)

func TestUsernameDeliveryOptIn(t *testing.T) {
	for _, opt := range []string{"", `,"include_username":false`, `,"include_username":true`} {
		for _, denied := range []bool{false, true} {
			s := &recordedStore{decision:postgres.Decision{Username:"alice", ID:"d1", Agent:postgres.Agent{NodeID:"n1", Generation:"g1"}}}
			if denied { s.decision.DenialReason = "no_vpn_group" }
			w := httptest.NewRecorder()
			New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/fetch", `{"generation":"g1","cid":0,"kid":2`+opt+`}`, "n1"))
			d, err := DecodeDecision(w.Body.Bytes())
			if w.Code != 200 || err != nil { t.Fatal("fetch failed") }
			want := ""
			if opt == `,"include_username":true` && !denied { want = "alice" }
			if d.Username != want { t.Fatal("username disclosure boundary broken") }
			if want == "" && strings.Contains(w.Body.String(), "username") { t.Fatal("legacy/denial envelope changed") }
		}
	}
	for _, body := range []string{
		`{"generation":"g1","cid":0,"kid":2,"username":"spoofed"}`,
		`{"generation":"g1","cid":0,"kid":2,"include_username":null}`,
		`{"generation":"g1","cid":0,"kid":2,"include_username":"true"}`,
		`{"generation":"g1","cid":0,"kid":2,"include_username":true,"include_username":false}`,
		`{"generation":"g1","cid":0,"kid":2,"Include_username":true}`,
	} {
		s := &recordedStore{}; w := httptest.NewRecorder()
		New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/fetch", body, "n1"))
		if w.Code != 400 || s.calls != 0 { t.Fatal("untrusted request field accepted") }
	}
	s := &recordedStore{}; w := httptest.NewRecorder()
	New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/heartbeat", `{"generation":"g1","include_username":true}`, "n1"))
	if w.Code != 400 || s.calls != 0 { t.Fatal("username opt-in accepted outside fetch") }
}

func TestUsernameDecisionBounds(t *testing.T) {
	for _, username := range []string{"alice", "\u0421\u0442\u0430\u043d\u0456\u0441\u043b\u0430\u0432", "alice\"\r\n\t\u202e", strings.Repeat("a",1024), strings.Repeat("a",1025), "alice\x00"} {
		d := Decision{ID:"d", NodeID:"n", Generation:"g", Username:username}
		body, _ := json.Marshal(d)
		got, err := DecodeDecision(body)
		valid := len(username) <= 1024 && !strings.ContainsRune(username, 0)
		if valid && (err != nil || got.Username != username) || !valid && err == nil { t.Fatal("username bounds not enforced") }
	}
	d := Decision{ID:"d", NodeID:"n", Generation:"g"}
	body, _ := json.Marshal(d)
	if got, err := DecodeDecision(body); err != nil || got.Username != "" { t.Fatal("legacy decision refused") }
	for _, field := range []string{`"username":null,`, `"username":123,`, `"username":"a","username":"b",`, `"Username":"a",`} {
		if _, err := DecodeDecision([]byte(strings.Replace(string(body), "{", "{"+field, 1))); err == nil { t.Fatal("ambiguous username accepted") }
	}
}
