// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/metrics"
)

var metricOperations = [...]string{"rotate", "heartbeat", "register", "fetch", "ack", "cancel"}
var metricResults = [...]string{"success", "retryable", "refused", "error"}
var durationBounds = [...]float64{.01, .05, .1, .25, .5, 1, 2, 5, 10}

type groupMetrics struct{ sessions, disconnects, poolFailures, capacity uint64 }
type requestMetrics struct {
	results [len(metricResults)]uint64
	buckets [len(durationBounds)]uint64
	count   uint64
	seconds float64
}
type agentMetrics struct {
	// Group counters are protected by agent.mu. API observations have their own
	// lock and never acquire agent.mu; scraping cannot block API delivery.
	groups   map[string]*groupMetrics
	mu       sync.Mutex
	requests [len(metricOperations)]requestMetrics
}

func newAgentMetrics(c config) *agentMetrics {
	m := &agentMetrics{groups: map[string]*groupMetrics{}}
	if len(c.GroupPools) == 0 {
		return m
	}
	gateway := netip.MustParsePrefix(c.VPNNetwork).Addr().Next()
	for _, g := range c.GroupPools {
		counter := &groupMetrics{}
		for _, cidr := range g.ranges() {
			// Validated pools are disjoint IPv4 subnets inside the node network.
			prefix := netip.MustParsePrefix(cidr)
			counter.capacity += uint64(1)<<(32-prefix.Bits()) - 2
			if prefix.Contains(gateway) {
				counter.capacity--
			}
		}
		m.groups[g.GroupName] = counter
	}
	return m
}

func (a *agent) metricsHandler() http.Handler {
	return metrics.Handler(func(context.Context) ([]metrics.Family, error) {
		// Never wait for management I/O under the control-plane lock.
		if !a.mu.TryLock() {
			return nil, errors.New("snapshot busy")
		}
		defer a.mu.Unlock()
		m := a.telemetry
		if m == nil {
			return nil, errors.New("metrics disabled")
		}
		families := []metrics.Family{
			{Name: "supivpn_sessions_active", Help: "Observed established tunnels not yet confirmed disconnected, including closing tunnels.", Type: "gauge"},
			{Name: "supivpn_sessions_total", Help: "Tunnels first observed established by this agent; resets on restart.", Type: "counter"},
			{Name: "supivpn_disconnections_total", Help: "Previously established tunnels confirmed absent; resets on restart.", Type: "counter"},
			{Name: "supivpn_ip_pool_allocated", Help: "Addresses held by pending, established or closing connections across both transports.", Type: "gauge"},
			{Name: "supivpn_ip_pool_capacity", Help: "Usable addresses after network, broadcast and gateway exclusions; shared across transports.", Type: "gauge"},
			{Name: "supivpn_ip_allocation_failures_total", Help: "Address allocation attempts refused because the configured group pool was full.", Type: "counter"},
		}
		active, allocated := map[string]float64{}, map[string]float64{}
		for _, c := range a.connections {
			if !c.establishedAt.IsZero() {
				active[c.groupName]++
			}
		}
		if a.pools != nil {
			for _, l := range a.pools.leases {
				allocated[l.groupName]++
			}
		}
		for _, g := range a.config.GroupPools {
			name := g.GroupName
			counter := m.groups[name]
			values := [...]float64{active[name], float64(counter.sessions), float64(counter.disconnects), allocated[name], float64(counter.capacity), float64(counter.poolFailures)}
			for i, v := range values {
				families[i].Samples = append(families[i].Samples, metrics.Sample{Labels: []metrics.Label{{Name: "group", Value: name}}, Value: v})
			}
		}
		var management, initialized, lease float64
		if a.readyLocked() {
			management = 1
			if a.management.tunnelsInitialized() {
				initialized = 1
			}
		}
		if a.remote != nil {
			lease = max(0, a.remote.leaseUntil.Sub(a.now()).Seconds())
		}
		families = append(families,
			metrics.Gauge("supivpn_openvpn_management_up", "Whether all configured OpenVPN management connections are attached and open.", management),
			metrics.Gauge("supivpn_openvpn_initialized", "Whether all configured daemons reported tunnel initialization; no synchronous probe is made.", initialized),
			metrics.Gauge("supivpn_controller_lease_remaining_seconds", "Remaining locally trusted controller lease; zero when absent or expired.", lease))
		m.mu.Lock()
		requests := m.requests
		m.mu.Unlock()
		calls := metrics.Family{Name: "supivpn_controller_requests_total", Help: "Agent API calls including retries; success means API success, not VPN authorization.", Type: "counter"}
		duration := metrics.Family{Name: "supivpn_controller_request_duration_seconds", Help: "Agent API call duration including client transport work.", Type: "histogram"}
		for i, op := range metricOperations {
			r := requests[i]
			label := metrics.Label{Name: "operation", Value: op}
			for j, result := range metricResults {
				calls.Samples = append(calls.Samples, metrics.Sample{Labels: []metrics.Label{label, {Name: "result", Value: result}}, Value: float64(r.results[j])})
			}
			for j, bound := range durationBounds {
				duration.Samples = append(duration.Samples, metrics.Sample{Suffix: "_bucket", Labels: []metrics.Label{label, {Name: "le", Value: strconv.FormatFloat(bound, 'g', -1, 64)}}, Value: float64(r.buckets[j])})
			}
			duration.Samples = append(duration.Samples,
				metrics.Sample{Suffix: "_bucket", Labels: []metrics.Label{label, {Name: "le", Value: "+Inf"}}, Value: float64(r.count)},
				metrics.Sample{Suffix: "_sum", Labels: []metrics.Label{label}, Value: r.seconds},
				metrics.Sample{Suffix: "_count", Labels: []metrics.Label{label}, Value: float64(r.count)})
		}
		return append(families, calls, duration), nil
	})
}

type measuredAPI struct {
	agentclient.API
	metrics *agentMetrics
}

func (m measuredAPI) Call(ctx context.Context, operation string, r agentclient.Request) (*agentapi.Decision, error) {
	start := time.Now()
	decision, err := m.API.Call(ctx, operation, r)
	seconds := time.Since(start).Seconds()
	for i, op := range metricOperations {
		if op != operation {
			continue
		}
		result := 0
		if err != nil {
			result = 3
			if agentclient.Retryable(err) {
				result = 1
			} else if agentclient.Status(err) >= 400 {
				result = 2
			}
		}
		m.metrics.mu.Lock()
		sample := &m.metrics.requests[i]
		sample.results[result]++
		sample.count++
		sample.seconds += seconds
		for j, bound := range durationBounds {
			if seconds <= bound {
				sample.buckets[j]++
			}
		}
		m.metrics.mu.Unlock()
		break
	}
	return decision, err
}
