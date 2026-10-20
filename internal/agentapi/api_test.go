// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

type recordedStore struct {
	calls                int
	actor                postgres.Agent
	conn                 postgres.Connection
	previous, ticket, id string
	ttl                  time.Duration
	outcome              postgres.Outcome
	decision             postgres.Decision
	err                  error
}

// Only boolean readiness on the authenticated heartbeat can become a witness.
type readinessStore struct { recordedStore; ready bool }
func(s *readinessStore)HeartbeatStatus(ctx context.Context,a postgres.Agent,ready bool)error{
    s.ready=ready;return s.Heartbeat(ctx,a)
}
func TestHeartbeatReadiness(t *testing.T){
    for _,tc:=range []struct{body string;status int;ready bool}{
        { `{"generation":"g1","ready":true}`,204,true},
        { `{"generation":"g1","ready":false}`,204,false},
        { `{"generation":"g1"}`,204,false},
        { `{"generation":"g1","ready":null}`,400,false},
        { `{"generation":"g1","ready":"true"}`,400,false},
        { `{"generation":"g1","Ready":true}`,400,false},
        { `{"generation":"g1","ready":true,"ready":false}`,400,false},
    }{
        s:=&readinessStore{};w:=httptest.NewRecorder()
        New(s,time.Minute).ServeHTTP(w,requestFor("/agent/v1/heartbeat",tc.body,"node-a"))
        if w.Code!=tc.status || s.ready!=tc.ready || tc.status==400 && s.calls!=0{t.Fatal("unsafe readiness handling")}
    }
    s:=&readinessStore{};w:=httptest.NewRecorder()
    New(s,time.Minute).ServeHTTP(w,requestFor("/agent/v1/rotate",`{"generation":"g1","ready":true}`,"node-a"))
    if w.Code!=400 || s.calls!=0{t.Fatal("readiness allowed outside heartbeat")}
}


func (s *recordedStore) RotateNode(_ context.Context, node, prev, next string) error {
	s.calls++
	s.actor = postgres.Agent{NodeID: node, Generation: next}
	s.previous = prev
	return s.err
}
func (s *recordedStore) Heartbeat(_ context.Context, a postgres.Agent) error {
	s.calls++
	s.actor = a
	return s.err
}
func (s *recordedStore) Register(_ context.Context, a postgres.Agent, c postgres.Connection, ticket string, ttl time.Duration) error {
	s.calls++
	s.actor = a
	s.conn = c
	s.ticket = ticket
	s.ttl = ttl
	return s.err
}
func (s *recordedStore) Fetch(_ context.Context, a postgres.Agent, c postgres.Connection) (postgres.Decision, error) {
	s.calls++
	s.actor = a
	s.conn = c
	return s.decision, s.err
}
func (s *recordedStore) Acknowledge(_ context.Context, a postgres.Agent, id string, o postgres.Outcome) error {
	s.calls++
	s.actor = a
	s.id = id
	s.outcome = o
	return s.err
}
func (s *recordedStore) Cancel(_ context.Context, a postgres.Agent, c postgres.Connection) error {
	s.calls++
	s.actor = a
	s.conn = c
	return s.err
}

func requestFor(path, body, node string) *http.Request {
	r := httptest.NewRequest("POST", "http://controller"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if node != "" {
		r = r.WithContext(WithNode(r.Context(), node))
	}
	return r
}
func TestAgentIdentityAndOperations(t *testing.T) {
	s := &recordedStore{}
	h := New(s, time.Minute)
	r := requestFor("/agent/v1/rotate", `{"generation":"g1"}`, "")
	r.Header.Set("X-Node-ID", "node-a")
	r.Header.Set("Authorization", "node-a")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 403 || s.calls != 0 {
		t.Fatal("untrusted headers authorized a node")
	}
	for _, tc := range []struct{ path, body string }{
		{"/rotate", `{"generation":"g1","previous_generation":"g0"}`},
		{"/heartbeat", `{"generation":"g1"}`},
		{"/register", `{"generation":"g1","cid":0,"kid":2,"ticket":"` + strings.Repeat("a", 43) + `"}`},
		{"/cancel", `{"generation":"g1","cid":0,"kid":2}`},
		{"/ack", `{"generation":"g1","decision_id":"decision-a","outcome":"applied"}`},
	} {
		out = httptest.NewRecorder()
		h.ServeHTTP(out, requestFor("/agent/v1"+tc.path, tc.body, "node-a"))
		if out.Code != 204 || s.actor != (postgres.Agent{NodeID: "node-a", Generation: "g1"}) {
			t.Fatalf("%s not bound to authenticated node: %d", tc.path, out.Code)
		}
	}
	if s.ttl != time.Minute || s.ticket != strings.Repeat("a", 43) || s.previous != "g0" || s.id != "decision-a" || s.outcome != postgres.Applied || s.conn.CID != 0 {
		t.Fatal("operation parameters lost")
	}
	s.decision = postgres.Decision{ID: "decision-a", Agent: s.actor, Connection: s.conn, GroupName: "admins-vpn", ExpiresAt: time.Now().UTC(), SessionExpiresAt: time.Now().Add(time.Minute).UTC()}
	out = httptest.NewRecorder()
	h.ServeHTTP(out, requestFor("/agent/v1/fetch", `{"generation":"g1","cid":0,"kid":2}`, "node-a"))
	var d Decision
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &d) != nil || d.NodeID != "node-a" || d.ID != "decision-a" || d.GroupName != "admins-vpn" || !d.ExpiresAt.Equal(s.decision.ExpiresAt) {
		t.Fatal("decision binding or deadlines changed in transport")
	}
}
func TestAgentRejectsMalformedRequests(t *testing.T) {
	valid := `{"generation":"g1","cid":0,"kid":2}`
	cases := []struct {
		name, path, body string
		edit             func(*http.Request)
	}{
		{"duplicate", "/fetch", `{"generation":"g1","generation":"g2","cid":0,"kid":2}`, nil},
		{"unknown-node", "/fetch", `{"generation":"g1","cid":0,"kid":2,"node_id":"node-b"}`, nil},
		{"nested", "/fetch", `{"generation":{"id":"g1"},"cid":0,"kid":2}`, nil},
		{"null", "/fetch", `{"generation":"g1","cid":null,"kid":2}`, nil},
		{"missing-cid", "/fetch", `{"generation":"g1","kid":2}`, nil},
		{"negative", "/fetch", `{"generation":"g1","cid":-1,"kid":2}`, nil},
		{"heartbeat-cid", "/heartbeat", `{"generation":"g1","cid":0,"kid":2}`, nil},
		{"heartbeat-rotate", "/heartbeat", `{"generation":"g1","previous_generation":"g0"}`, nil},
		{"trailing", "/fetch", valid + " {}", nil},
		{"too-large", "/fetch", valid + strings.Repeat(" ", 8192), nil},
		{"bad-ticket", "/register", `{"generation":"g1","cid":0,"kid":2,"ticket":"short"}`, nil},
		{"wrong-operation", "/fetch", `{"generation":"g1","cid":0,"kid":2,"ticket":"other"}`, nil},
		{"removed-renewal", "/register", `{"generation":"g1","cid":0,"kid":2,"renewal":true,"ticket":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, nil},
		{"removed-renewal-false", "/register", `{"generation":"g1","cid":0,"kid":2,"renewal":false,"ticket":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, nil},
		{"bad-outcome", "/ack", `{"generation":"g1","decision_id":"d1","outcome":"maybe"}`, nil},
		{"query", "/fetch?node_id=node-b", valid, nil},
		{"encoded-path", "/fetch", valid, func(r *http.Request) { r.URL.RawPath = "/agent/v1/%66etch" }},
		{"method", "/fetch", valid, func(r *http.Request) { r.Method = "GET" }},
		{"media", "/fetch", valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &recordedStore{}
			r := requestFor("/agent/v1"+tc.path, tc.body, "node-a")
			if tc.edit != nil {
				tc.edit(r)
			}
			out := httptest.NewRecorder()
			New(s, time.Minute).ServeHTTP(out, r)
			if out.Code < 400 || out.Code >= 500 || s.calls != 0 {
				t.Fatalf("malformed request reached store: status=%d calls=%d", out.Code, s.calls)
			}
		})
	}
}
func TestAgentErrorsAreBoundedAndGeneric(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{{postgres.ErrNoDecision, 204}, {postgres.ErrConflict, 409}, {postgres.ErrGeneration, 409}, {controller.ErrLoginExpired, 410}, {errors.New("internal database detail"), 503}} {
		s := &recordedStore{err: tc.err}
		out := httptest.NewRecorder()
		New(s, time.Minute).ServeHTTP(out, requestFor("/agent/v1/fetch", `{"generation":"g1","cid":0,"kid":2}`, "node-a"))
		if out.Code != tc.want || strings.Contains(out.Body.String(), "database detail") || out.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected error response: %d", out.Code)
		}
	}
}

func TestUnlimitedDecisionEnvelope(t *testing.T) {
    base := Decision{ID:"d1",NodeID:"node-a",Generation:"g1",CID:1,KID:2,
        GroupName:"admins-vpn",ExpiresAt:time.Now().Add(time.Minute),SessionUnlimited:true}
    data,err:=json.Marshal(base)
    if err!=nil {t.Fatal(err)}
    got,err:=DecodeDecision(data)
    if err!=nil || !got.SessionUnlimited || !got.SessionExpiresAt.IsZero() {t.Fatal("explicit unlimited lost in transport")}
    for _,field:=range []string{`"session_unlimited":null`,`"session_unlimited":"true"`,`"session_unlimited":1`,`"ticket_hash":"old"`} {
        encoded:=strings.Replace(string(data),`"session_unlimited":true`,field,1)
        if _,err:=DecodeDecision([]byte(encoded));err==nil {t.Fatal("malformed or obsolete decision accepted")}
    }
}
