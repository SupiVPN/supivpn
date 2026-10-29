// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"net/http"
	"time"

	"supivpn/internal/metrics"
	"supivpn/internal/postgres"
)

func databaseMetrics(read func(context.Context) (postgres.MetricsSnapshot, error)) http.Handler {
	// Handler serializes collection. These are shared database gauges, not
	// per-process Lambda counters. Do not sum replicas reporting the same DB.
	var cached []metrics.Family
	var expires time.Time
	return metrics.Handler(func(ctx context.Context) ([]metrics.Family, error) {
		if cached != nil && time.Now().Before(expires) {
			return cached, nil
		}
		snapshot, err := read(ctx)
		if err != nil {
			return nil, err
		} // Never return an expired successful snapshot.
		nodes := metrics.Family{Name: "supivpn_controller_nodes", Help: "Database node records by lease/fencing state, shared by all controller replicas.", Type: "gauge"}
		for i, state := range []string{"ready", "expired", "stopping", "stopped"} {
			nodes.Samples = append(nodes.Samples, metrics.Sample{Labels: []metrics.Label{{Name: "state", Value: state}}, Value: float64(snapshot.Nodes[i])})
		}
		logins := metrics.Family{Name: "supivpn_controller_login_records", Help: "Retained database login records by state; acknowledged records are not a count of live tunnels.", Type: "gauge"}
		for i, state := range []string{"pending", "started", "decided", "acknowledged", "cancelled"} {
			logins.Samples = append(logins.Samples, metrics.Sample{Labels: []metrics.Label{{Name: "state", Value: state}}, Value: float64(snapshot.Logins[i])})
		}
		cached = []metrics.Family{nodes, logins,
			metrics.Gauge("supivpn_controller_reserved_slots", "Database admission slots retained until cancellation or confirmed fencing; not live tunnels.", float64(snapshot.ReservedSlots)),
			metrics.Gauge("supivpn_controller_snapshot_timestamp_seconds", "Unix time at which the database snapshot completed; cached for at most five seconds per process.", float64(time.Now().Unix()))}
		expires = time.Now().Add(5 * time.Second)
		return cached, nil
	})
}
