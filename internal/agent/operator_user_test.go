// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func operatorFixture(t *testing.T) (*agent, chan string) {
	t.Helper()
	a, commands := remoteFixture(t, nil)
	for cid, user := range map[uint64]string{1: "alice", 2: "alice", 3: "Alice", 4: "alice-other"} {
		ip, err := a.pools.acquire(cid, coreGroup)
		if err != nil {
			t.Fatal(err)
		}
		a.connections[cid] = &connection{cid: cid, kid: 2, active: true, groupName: coreGroup, address: ip,
			subjectHash: sha256.Sum256([]byte("https://idp.example.test\x00" + user)), expires: time.Now().Add(time.Hour)}
	}
	return a, commands
}

func TestOperatorDropExactUserAndConfirmedDisconnect(t *testing.T) {
	a, commands := operatorFixture(t)
	ctx := context.Background()
	issuer := "https://idp.example.test"
	q := userSessionsRequest{Operation: "status", Username: "alice"}
	out, err := a.userSessions(ctx, issuer, q)
	if err != nil || out.Matched != 2 || out.Requested != 0 || len(commands) != 0 {
		t.Fatal("preview changed tunnels")
	}
	q.Operation = "drop"
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.userSessions(ctx, issuer, q); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got := map[string]bool{<-commands: true, <-commands: true}
	if !got["client-kill 1"] || !got["client-kill 2"] || len(commands) != 0 {
		t.Fatal("wrong/duplicate kill")
	}
	if len(a.pools.leases) != 4 || len(a.remote.jobs) != 0 {
		t.Fatal("kill released an IP/controller slot before DISCONNECT")
	}
	if a.connections[3].closing || a.connections[4].closing {
		t.Fatal("case/partial username match killed another user")
	}
	q.Operation = "status"
	out, err = a.userSessions(ctx, issuer, q)
	if err != nil || out.Matched != 2 || out.Closing != 2 {
		t.Fatal("kill ACK reported termination")
	}
	for _, cid := range []uint64{1, 2} {
		a.handleEvent(clientEvent{kind: "DISCONNECT", cid: cid})
	}
	out, err = a.userSessions(ctx, issuer, q)
	if err != nil || out.Matched != 0 || len(a.pools.leases) != 2 || len(a.remote.jobs) != 2 {
		t.Fatal("disconnect did not cancel normally")
	}
	// CID reuse by a different subject must not be affected by an operator retry.
	a.connections[1] = &connection{cid: 1, active: true, subjectHash: sha256.Sum256([]byte(issuer + "\x00bob"))}
	q.Operation = "drop"
	if _, err = a.userSessions(ctx, issuer, q); err != nil || a.connections[1].closing || len(commands) != 0 {
		t.Fatal("retry killed reused CID")
	}
}

func TestOperatorUnknownIdentityIssuerAndOutage(t *testing.T) {
	a, commands := operatorFixture(t)
	ctx := context.Background()
	q := userSessionsRequest{Operation: "drop", Username: "alice"}
	out, err := a.userSessions(ctx, "https://another-idp.example.test", q)
	if err != nil || out.Matched != 0 || len(commands) != 0 {
		t.Fatal("cross-issuer match")
	}
	a.connections[5] = &connection{cid: 5, active: true}
	a.connections[6] = &connection{cid: 6} // no authenticated tunnel yet
	out, err = a.userSessions(ctx, "https://idp.example.test", q)
	if err != nil || out.Unidentified != 1 || out.Requested != 2 || a.connections[5].closing {
		t.Fatal("unidentified session guessed")
	}
	<-commands
	<-commands
	a.now = func() time.Time { return time.Now().Add(time.Minute) }
	a.expire()
	select {
	case <-a.management.done:
	default:
		t.Fatal("unconfirmed kill left pair running")
	}
	if _, err = a.userSessions(ctx, "https://idp.example.test", q); err == nil {
		t.Fatal("dead management reported zero sessions")
	}
	if len(a.pools.leases) != 4 {
		t.Fatal("kill timeout released addresses")
	}
}

func TestOperatorRejectsMalformedRequests(t *testing.T) {
	a, commands := operatorFixture(t)
	h := a.userSessionsHandler("https://idp.example.test")
	for _, body := range []string{
		`{}`, `null`, `{"operation":"drop","username":null}`, `{"operation":"kill","username":"alice"}`,
		`{"operation":"drop","username":""}`, `{"operation":"drop","username":"alice\nclient-kill 3"}`,
		`{"operation":"drop","username":"alice","username":"Alice"}`,
		`{"operation":"status","operation":"drop","username":"alice"}`,
		`{"Operation":"drop","username":"alice"}`, `{"operation":"drop","username":" alice"}`,
		`{"operation":"drop","username":"alice","cid":3}`, `{"operation":"drop","username":["alice"]}`,
		`{"operation":true,"username":"alice"}`, `{"operation":"drop","username":7}`,
		`{"operation":"drop","username":{}}`, `{"operation":"drop","user\u006eame":"alice","username":"Alice"}`,
		`{"operation":"drop","username":"\ud800"}`, `{"operation":"drop","username":"alice"} {}`,
		`{"operation":"drop","username":"` + strings.Repeat("a", 2048) + `"}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "http://local/user-sessions", strings.NewReader(body)))
		if w.Code != 400 || len(commands) != 0 {
			t.Fatal("malformed operator request reached management")
		}
	}
	for _, path := range []string{"/agent/v1/fetch", "/user-sessions?execute=true", "/%75ser-sessions"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "http://local"+path, strings.NewReader(`{"operation":"drop","username":"alice"}`)))
		if w.Code != 400 || len(commands) != 0 {
			t.Fatal("alternative path accepted")
		}
	}
}

func TestOperatorPrivateSocketAndClient(t *testing.T) {
	a, commands := operatorFixture(t)
	dir, err := os.MkdirTemp("", "supivpn-op-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a.config.ManagementSocket = filepath.Join(dir, "management.sock")
	server, _, err := a.listenOperator("https://idp.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	socket := operatorSocket(a.config.ManagementSocket)
	info, err := os.Lstat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("operator socket is not private")
	}
	if duplicate, _, err := a.listenOperator("https://idp.example.test"); err == nil {
		duplicate.Close()
		t.Fatal("existing socket replaced")
	}
	var reply bytes.Buffer
	err = requestUserSessions(context.Background(), socket, strings.NewReader(`{"operation":"drop","username":"alice"}`), &reply)
	var out userSessionsResult
	if err != nil || json.Unmarshal(reply.Bytes(), &out) != nil || out.Requested != 2 {
		t.Fatal("operator RPC failed", err)
	}
	<-commands
	<-commands
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = requestUserSessions(cancelled, socket, strings.NewReader(`{"operation":"drop","username":"Alice"}`), &reply); err == nil || len(commands) != 0 {
		t.Fatal("cancelled client mutated")
	}
	for _, path := range []string{"/user-sessions", "/operator/user-sessions"} {
		w := httptest.NewRecorder()
		a.remoteHealth().ServeHTTP(w, httptest.NewRequest("POST", a.origin.String()+path, strings.NewReader(`{"operation":"drop","username":"alice"}`)))
		if w.Code != 404 {
			t.Fatal("operator exposed on public listener")
		}
	}
}
