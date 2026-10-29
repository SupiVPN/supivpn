// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"supivpn/internal/metrics"
	"supivpn/internal/postgres"
)

func TestMetricsDatabaseSnapshotAndCache(t *testing.T) {
	calls := 0
	h := databaseMetrics(func(ctx context.Context) (postgres.MetricsSnapshot, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded query")
		}
		return postgres.MetricsSnapshot{Nodes: [4]int64{2, 1, 0, 0}, Logins: [5]int64{1, 2, 3, 9, 5}, ReservedSlots: 4}, nil
	})
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `supivpn_controller_login_records{state="acknowledged"} 9`) || !strings.Contains(w.Body.String(), "supivpn_controller_reserved_slots 4") {
			t.Fatal("database metrics not distinguished")
		}
	}
	if calls != 1 {
		t.Fatal("snapshot cache missed")
	}
	h = databaseMetrics(func(context.Context) (postgres.MetricsSnapshot, error) {
		return postgres.MetricsSnapshot{}, errors.New("private connection details")
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	if w.Code != 503 || w.Body.Len() != 0 {
		t.Fatal("database error reported as healthy zeros or leaked")
	}
}

func TestMetricsDefaultAndAdapterConfiguration(t *testing.T) {
	c, err := ParseConfig("{}")
	if err != nil || c.Metrics.IsEnabled() {
		t.Fatal("metrics enabled by default")
	}
	c, err = ParseConfig(`{"metrics":{"enabled":false,"listen":"saved-invalid"}}`)
	if err != nil || c.Metrics.IsEnabled() {
		t.Fatal("explicit opt-out failed")
	}
	if _, err = ParseConfig(`{"metrics":{"enabled":true}}`); err == nil {
		t.Fatal("enabled insecure metrics accepted")
	}
	c = Config{Metrics: &metrics.Config{Enabled: true}}
	if _, err = OpenAgent(context.Background(), c, "", nil); err == nil {
		t.Fatal("agent Lambda accepted metrics")
	}
}
