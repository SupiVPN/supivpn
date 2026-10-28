// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

type recoveryStub struct {
	mu            sync.Mutex
	power         map[string]string
	starts, stops map[string]int
	failStart     bool
}

func (f *recoveryStub) Managed(n string) bool { return n != "retired" }
func (f *recoveryStub) Power(_ context.Context, n string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.power[n], nil
}
func (f *recoveryStub) Stop(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops[n]++
	f.power[n] = "stopping"
	return nil
}
func (f *recoveryStub) Start(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts[n]++
	if f.failStart {
		return errors.New("private provider details")
	}
	f.power[n] = "pending"
	return nil
}

func TestAutomaticRecoveryIntegration(t *testing.T) {
	pool, replica := integrationDatabase(t)
	ctx := context.Background()
	f := &recoveryStub{}
	s := postgres.NewWithFencer(pool, f)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture SQL: %v", err)
		}
	}
	phase := func(node string) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, "SELECT phase FROM supivpn.node_recovery WHERE node_id=$1", node).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	fence := func(node string) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, "SELECT fence_state FROM supivpn.nodes WHERE node_id=$1", node).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	step := func() {
		t.Helper()
		exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
		if err := s.FenceExpired(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		t.Helper()
		exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes CASCADE")
		f.power = map[string]string{"node-a": "running", "node-b": "running", "node-c": "running", "retired": "running"}
		f.starts, f.stops, f.failStart = map[string]int{}, map[string]int{}, false
		for _, n := range []string{"node-a", "node-b", "node-c"} {
			a := postgres.Agent{NodeID: n, Generation: "old"}
			if err := s.RotateNode(ctx, n, "", "old"); err != nil {
				t.Fatal(err)
			}
			if err := s.HeartbeatStatus(ctx, a, true); err != nil {
				t.Fatal(err)
			}
		}
		exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
	}
	grant := func(node string, id int64) error {
		t.Helper()
		a := postgres.Agent{NodeID: node, Generation: "old"}
		ticket := fmt.Sprintf("ticket-%040d", id)
		h := sha256.Sum256([]byte(ticket))
		if err := registerOwnedFixture(t, s, ctx, a, postgres.Connection{CID: id, KID: 1}, ticket, time.Minute, sha256.Sum256([]byte("same-user"))); err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx, ticket, fmt.Sprintf("request-%d", id), h); err != nil {
			t.Fatal(err)
		}
		p, err := s.Lookup(ctx, ticket, h)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		return s.Complete(ctx, p, controller.Authorization{SubjectHash: sha256.Sum256([]byte("same-user")),
			MaxConnections: 1, AssertionHash: h, GroupName: "admins-vpn", AssertionExpiresAt: now.Add(time.Minute),
			NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)})
	}
	t.Run("stop-confirm-start-new-generation-healthy-and-slots", func(t *testing.T) {
		reset()
		exec("UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE node_id='node-a'")
		if err := grant("node-a", 1); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal(err)
		}
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
		step()
		step()
		if f.stops["node-a"] != 1 || fence("node-a") != "stopping" {
			t.Fatal("stop not requested")
		}
		if err := grant("node-b", 2); !errors.Is(err, controller.ErrConnectionLimit) {
			t.Fatal("slot released before confirmed stop")
		}
		if err := s.RotateNode(ctx, "node-a", "old", "new"); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("rotation during Stop")
		}
		step()
		if f.starts["node-a"] != 0 {
			t.Fatal("start before stopped")
		}
		f.power["node-a"] = "stopped"
		step()
		if fence("node-a") != "stopped" {
			t.Fatal("not fenced")
		}
		if err := grant("node-b", 3); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("confirmed fencing did not free slot")
		}
		step()
		if f.starts["node-a"] != 1 {
			t.Fatal("no automatic start")
		}
		step()
		if phase("node-a") != "verify" {
			t.Fatal("not waiting for recovery")
		}
		f.power["node-a"] = "running"
		step()
		if phase("node-a") != "verify" {
			t.Fatal("EC2 running mistaken for service health")
		}
		if err := s.RotateNode(ctx, "node-a", "old", "new"); err != nil {
			t.Fatal(err)
		}
		if err := s.HeartbeatStatus(ctx, postgres.Agent{NodeID: "node-a", Generation: "new"}, true); err != nil {
			t.Fatal(err)
		}
		step()
		if phase("node-a") != "verify" {
			t.Fatal("unstable health accepted")
		}
		exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '31 seconds' WHERE node_id='node-a'")
		f.power["node-a"] = "pending"
		step()
		if phase("node-a") != "verify" {
			t.Fatal("heartbeat accepted while EC2 is not running")
		}
		f.power["node-a"] = "running"
		step()
		if phase("node-a") != "complete" {
			t.Fatal("healthy recovery not completed")
		}
		if err := s.HeartbeatStatus(ctx, postgres.Agent{NodeID: "node-a", Generation: "old"}, true); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("old generation resurrected")
		}
	})
	t.Run("common-outage-never-stops-instances", func(t *testing.T) {
		reset()
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch'")
		for range 5 {
			step()
		}
		if len(f.stops) != 0 || len(f.starts) != 0 {
			t.Fatal("common outage caused cloud mutation")
		}
		if fence("node-a") != "ready" {
			t.Fatal("common outage blocked clean self-restart")
		}
	})
	t.Run("one-active-recovery-across-replicas", func(t *testing.T) {
		reset()
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-b'")
		other := postgres.NewWithFencer(replica, f)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				x := s
				if i%2 == 0 {
					x = other
				}
				errs <- x.FenceExpired(ctx)
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		current := phase("node-a")
		if (current != "inspect" && current != "stop") || fence("node-b") != "ready" {
			t.Fatal("parallel recovery selected another node")
		}
		// A contended observation may defer its transition until the next tick.
		// It must keep the same sole job and still make bounded progress.
		var active int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.node_recovery WHERE phase IN ('inspect','stop','start','verify')").Scan(&active); err != nil || active != 1 {
			t.Fatal("multiple active recovery jobs")
		}
		if current == "inspect" {
			step()
		}
		step()
		step()
		if f.stops["node-a"] != 1 || f.stops["node-b"] != 0 {
			t.Fatal("multiple nodes stopped")
		}
	})
	t.Run("witness-lost-before-stop", func(t *testing.T) {
		reset()
		step()
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch'")
		step()
		if len(f.stops) != 0 || fence("node-a") != "ready" {
			t.Fatal("lost peer caused stop or blocked clean restart")
		}
	})
	t.Run("fresh-heartbeat-without-service-health-is-not-witness", func(t *testing.T) {
		reset()
		exec("UPDATE supivpn.nodes SET healthy_since=NULL")
		step()
		if len(f.stops) != 0 || fence("node-a") != "ready" {
			t.Fatal("unready peer accepted")
		}
	})
	t.Run("start-owned-stop-even-without-witness", func(t *testing.T) {
		reset()
		step()
		step()
		f.power["node-a"] = "stopped"
		step()
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch'")
		step()
		if f.starts["node-a"] != 1 {
			t.Fatal("recovery cannot restore last node")
		}
	})
	t.Run("operator-stopped-node-not-started", func(t *testing.T) {
		for _, between := range []bool{false, true} {
			reset()
			if between {
				step()
			}
			f.power["node-a"] = "stopped"
			step()
			if phase("node-a") != "complete" || len(f.starts) != 0 || len(f.stops) != 0 {
				t.Fatal("operator stop reversed")
			}
		}
	})
	t.Run("start-budget-persists-and-blocks-cascade", func(t *testing.T) {
		reset()
		step()
		step()
		f.power["node-a"] = "stopped"
		step()
		f.failStart = true
		for range 3 {
			exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
			if err := postgres.NewWithFencer(replica, f).FenceExpired(ctx); !errors.Is(err, controller.ErrUnavailable) {
				t.Fatal("start error not opaque")
			}
		}
		step()
		if f.starts["node-a"] != 3 || phase("node-a") != "blocked" {
			t.Fatal("unbounded start attempts")
		}
		exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-b'")
		step()
		if f.stops["node-b"] != 0 || fence("node-b") != "ready" {
			t.Fatal("circuit breaker allowed cascading recovery")
		}
	})
	t.Run("deadline-blocks-without-freeing-uncertain-slot", func(t *testing.T) {
		reset()
		step()
		step()
		exec("UPDATE supivpn.node_recovery SET deadline='epoch'")
		step()
		if phase("node-a") != "blocked" || fence("node-a") != "stopping" || len(f.starts) != 0 {
			t.Fatal("unsafe recovery timeout")
		}
	})
	t.Run("cooldown-bounds-cloud-work", func(t *testing.T) {
		reset()
		step()
		step()
		for range 20 {
			if err := s.FenceExpired(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if f.stops["node-a"] != 1 || len(f.starts) != 0 {
			t.Fatal("polling ignored cooldown")
		}
	})
	t.Run("hourly-budget-survives-new-job", func(t *testing.T) {
		reset()
		exec("INSERT INTO supivpn.node_recovery_starts(node_id,attempted_at) SELECT 'node-b',clock_timestamp()-n*interval '1 minute' FROM generate_series(1,3) n")
		step()
		if fence("node-a") != "ready" || len(f.stops) != 0 {
			t.Fatal("hourly budget ignored")
		}
	})
}
