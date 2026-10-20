// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
    "bufio"
    "fmt"
    "net"
    "net/http/httptest"
    "testing"
    "time"
)

func TestNLBReadiness(t *testing.T) {
    a, commands := remoteFixture(t, nil)
    check := func(target string, want int) {
        t.Helper()
        w := httptest.NewRecorder()
        a.remoteHealth().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
        if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
            t.Fatalf("readiness status=%d, want %d", w.Code, want)
        }
    }
    check("https://10.0.0.5:1194/readyz", 503)
    a.management.initialized.Store(true)
    check("https://10.0.0.5:1194/readyz", 200)
    if got := <-commands; got != "pid" { t.Fatal("daemon was not probed") }
    check("https://10.0.0.6:1194/readyz", 200)
    if len(commands) != 0 { t.Fatal("NLB probes were not coalesced") }
    check("https://10.0.0.5:1194/saml/acs", 404)
    check("https://10.0.0.5:1194/healthz", 404)
    check("https://10.0.0.5:1194/readyz?x=1", 404)
    check("http://10.0.0.5:1194/readyz", 404)
    a.management.close()
    check("https://10.0.0.5:1194/readyz", 503)
}

func TestReadinessTracksOpenVPNState(t *testing.T) {
    client, peer := net.Pipe()
    m := newManagement(client)
    defer m.close()
    defer peer.Close()
    for _, state := range []struct{ value string; ready bool }{
        {"1,ASSIGN_IP,,10.0.0.1", false},
        {"2,CONNECTED,SUCCESS,10.0.0.1", true},
        {"3,RECONNECTING,signal", false},
        {"4,CONNECTED,SUCCESS,10.0.0.1", true},
        {"5,EXITING,SIGTERM", false},
    } {
        // A reply after the state event is a barrier for the parser goroutine.
        go fmt.Fprintf(peer, ">STATE:%s\nSUCCESS: barrier\n", state.value)
        select {
        case <-m.replies:
        case <-time.After(time.Second): t.Fatal("state parser stalled")
        }
        if m.initialized.Load() != state.ready { t.Fatal("incorrect OpenVPN readiness") }
    }
}

func TestUnresponsiveDaemonFailsReadiness(t *testing.T) {
    a, _ := remoteFixture(t, nil)
    a.management.close()
    client, peer := net.Pipe()
    m := newManagement(client)
    defer m.close()
    defer peer.Close()
    a.attach(m)
    m.initialized.Store(true)
    go func() {
        s := bufio.NewScanner(peer)
        if s.Scan() && s.Text() == "pid" { fmt.Fprintln(peer, "ERROR: daemon unavailable") }
    }()
    w := httptest.NewRecorder()
    a.remoteHealth().ServeHTTP(w, httptest.NewRequest("GET", "https://10.0.0.5/readyz", nil))
    if w.Code != 503 { t.Fatal("unresponsive daemon advertised healthy") }
    select { case <-m.done: default: t.Fatal("failed probe did not restart the pair") }
}
