// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/metrics"
)

func metricsAgent(t *testing.T) *agent {
	t.Helper()
	c := groupConfig()
	c.TCPManagementSocket = "/synthetic/tcp"
	c.Metrics = &metrics.Config{Enabled: true}
	origin, _ := url.Parse("https://vpn.example.test")
	a := newAgent(c, origin)
	a.pools = newPoolAllocator(c)
	a.attach(&management{done: make(chan struct{})})
	return a
}

func scrapeAgent(t *testing.T, a *agent) string {
	t.Helper()
	w := httptest.NewRecorder()
	a.metricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("scrape failed: %d", w.Code)
	}
	return w.Body.String()
}

func TestMetricsSessionsPoolsAndDuplicateEvents(t *testing.T) {
	a := metricsAgent(t)
	for _, cid := range []uint64{7, transportCIDBit + 7} {
		address, err := a.pools.acquire(cid, coreGroup)
		if err != nil {
			t.Fatal(err)
		}
		a.connections[cid] = &connection{cid: cid, kid: 2, active: true, groupName: coreGroup, address: address, username: "never-export-this-user", ticket: "never-export-this-ticket"}
	}
	before := scrapeAgent(t, a)
	if !strings.Contains(before, `supivpn_sessions_active{group="admins-vpn"} 0`) || !strings.Contains(before, `supivpn_ip_pool_allocated{group="admins-vpn"} 2`) {
		t.Fatal("pending authorization counted as established")
	}
	for _, cid := range []uint64{7, transportCIDBit + 7} {
		a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: cid})
		a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: cid})
	}
	a.connections[7].closing = true
	text := scrapeAgent(t, a)
	for _, line := range []string{`supivpn_sessions_active{group="admins-vpn"} 2`, `supivpn_sessions_total{group="admins-vpn"} 2`, `supivpn_ip_pool_capacity{group="admins-vpn"} 61`} {
		if !strings.Contains(text, line) {
			t.Fatalf("missing metric %s", line)
		}
	}
	if strings.Contains(text, "never-export") || strings.Contains(text, "10.203.") || strings.Contains(text, "username") {
		t.Fatal("private labels exposed")
	}
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	a.handleEvent(clientEvent{kind: "STATUS", scoped: true, transport: 1, clients: map[uint64]struct{}{}})
	text = scrapeAgent(t, a)
	for _, line := range []string{`supivpn_sessions_active{group="admins-vpn"} 0`, `supivpn_disconnections_total{group="admins-vpn"} 2`, `supivpn_ip_pool_allocated{group="admins-vpn"} 0`} {
		if !strings.Contains(text, line) {
			t.Fatalf("missing metric %s", line)
		}
	}
	// Observability must not wait for management I/O holding the agent lock.
	a.mu.Lock()
	w := httptest.NewRecorder()
	a.metricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	a.mu.Unlock()
	if w.Code != 503 {
		t.Fatal("busy snapshot not refused")
	}
}

func TestMetricsCapacityMatchesAllocatorAcrossCIDRs(t *testing.T) {
	for _, tc := range []struct {
		name string
		pool groupPool
		want int
	}{
		{"gateway", groupPool{CIDR: "10.203.0.0/30"}, 1},
		{"no_gateway", groupPool{CIDR: "10.203.0.8/30"}, 2},
		{"multiple", groupPool{CIDRs: []string{"10.203.0.0/30", "10.203.0.8/30"}}, 3},
		{"whole_network", groupPool{CIDR: "10.203.0.0/24"}, 253},
		{"broadcast_edge", groupPool{CIDR: "10.203.0.248/29"}, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := groupConfig()
			tc.pool.GroupName, tc.pool.Priority = coreGroup, 1
			c.GroupPools = []groupPool{tc.pool}
			c.Metrics = &metrics.Config{Enabled: true}
			a := newAgent(c, &url.URL{})
			a.pools = newPoolAllocator(c)
			var count int
			for cid := uint64(0); ; cid++ {
				_, err := a.pools.acquire(cid, coreGroup)
				if errors.Is(err, errPoolFull) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
			}
			if count != tc.want || !strings.Contains(scrapeAgent(t, a), `supivpn_ip_pool_capacity{group="admins-vpn"} `+strconv.Itoa(tc.want)+"\n") {
				t.Fatal("capacity differs from actual allocator")
			}
		})
	}
}

type metricAPI func(context.Context, string, agentclient.Request) (*agentapi.Decision, error)

func (f metricAPI) Call(ctx context.Context, op string, r agentclient.Request) (*agentapi.Decision, error) {
	return f(ctx, op, r)
}

func TestMetricsControllerCallsAndLease(t *testing.T) {
	a := metricsAgent(t)
	api := measuredAPI{API: metricAPI(func(context.Context, string, agentclient.Request) (*agentapi.Decision, error) {
		return nil, &agentclient.Error{Status: 503}
	}), metrics: a.telemetry}
	_, _ = api.Call(context.Background(), "cancel", agentclient.Request{})
	_, _ = api.Call(context.Background(), "untrusted-not-a-label", agentclient.Request{})
	a.remote = &remoteAgent{leaseUntil: a.now().Add(-time.Second)}
	text := scrapeAgent(t, a)
	if !strings.Contains(text, `supivpn_controller_requests_total{operation="cancel",result="retryable"} 1`) || !strings.Contains(text, "supivpn_controller_lease_remaining_seconds 0") || strings.Contains(text, "untrusted-not-a-label") {
		t.Fatal("request accounting or label boundary failed")
	}
}
