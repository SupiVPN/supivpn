// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

func TestHeartbeatReadinessAndFailure(t *testing.T) {
	pool, replica := integrationDatabase(t)
	ctx := context.Background()
	store := postgres.New(replica)
	actor := postgres.Agent{NodeID: "heartbeat-readiness", Generation: "g1"}
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.nodes CASCADE"); err != nil {
		t.Fatal("cannot reset disposable nodes")
	}
	if err := store.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
		t.Fatal("cannot register heartbeat fixture")
	}
	read := func() (time.Time, *time.Time) {
		t.Helper()
		var lease time.Time
		var healthy *time.Time
		if err := pool.QueryRow(ctx, "SELECT lease_expires_at,healthy_since FROM supivpn.nodes WHERE node_id=$1", actor.NodeID).Scan(&lease, &healthy); err != nil {
			t.Fatal("cannot read committed heartbeat state")
		}
		return lease, healthy
	}
	if err := store.HeartbeatStatus(ctx, actor, true); err != nil {
		t.Fatal("ready heartbeat failed")
	}
	_, firstHealthy := read()
	if firstHealthy == nil {
		t.Fatal("ready heartbeat did not establish health")
	}
	if err := store.HeartbeatStatus(ctx, actor, true); err != nil {
		t.Fatal("repeated ready heartbeat failed")
	}
	lease, healthy := read()
	if healthy == nil || !healthy.Equal(*firstHealthy) {
		t.Fatal("repeated heartbeat reset the stable-health interval")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.HeartbeatStatus(cancelled, actor, false); !errors.Is(err, controller.ErrUnavailable) {
		t.Fatal("cancelled heartbeat did not fail closed")
	}
	unchanged, healthy := read()
	if !unchanged.Equal(lease) || healthy == nil || !healthy.Equal(*firstHealthy) {
		t.Fatal("failed heartbeat changed durable readiness or lease")
	}
	if err := store.HeartbeatStatus(ctx, actor, false); err != nil {
		t.Fatal("unready heartbeat failed")
	}
	if _, healthy := read(); healthy != nil {
		t.Fatal("unready heartbeat retained witness health")
	}
	for _, unavailable := range []*postgres.Store{nil, postgres.New(nil)} {
		if err := unavailable.HeartbeatStatus(ctx, actor, true); !errors.Is(err, controller.ErrUnavailable) {
			t.Fatal("missing database did not fail closed")
		}
	}
}

func TestHeartbeatRechecksConcurrentNodeChange(t *testing.T) {
	pool, replica := integrationDatabase(t)
	testHeartbeatRechecksConcurrentNodeChange(t, pool, postgres.New(replica))
}

func testHeartbeatRechecksConcurrentNodeChange(t *testing.T, pool *pgxpool.Pool, store *postgres.Store) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "TRUNCATE supivpn.nodes CASCADE"); err != nil {
			t.Error("cannot clean up disposable heartbeat nodes")
		}
	})
	actor := postgres.Agent{NodeID: "heartbeat-concurrent", Generation: "g1"}
	for _, change := range []struct {
		name, sql          string
		expireWhileWaiting bool
	}{
		{"expired", "UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id=$1", false},
		{"rotated", "UPDATE supivpn.nodes SET generation='g2' WHERE node_id=$1", false},
		{"fenced", "UPDATE supivpn.nodes SET fence_state='stopped' WHERE node_id=$1", false},
		{"expired-while-waiting", "SELECT node_id FROM supivpn.nodes WHERE node_id=$1 FOR UPDATE", true},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, "TRUNCATE supivpn.nodes CASCADE"); err != nil {
				t.Fatal("cannot reset disposable nodes")
			}
			if err := store.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
				t.Fatal("cannot register heartbeat fixture")
			}
			if change.expireWhileWaiting {
				if _, err := pool.Exec(ctx, "UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()+interval '500 milliseconds' WHERE node_id=$1", actor.NodeID); err != nil {
					t.Fatal("cannot shorten test lease")
				}
			}
			lock, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal("cannot start node change")
			}
			defer lock.Rollback(ctx)
			if _, err = lock.Exec(ctx, change.sql, actor.NodeID); err != nil {
				t.Fatal("cannot change locked node")
			}
			completed := make(chan error, 1)
			go func() { completed <- store.HeartbeatStatus(ctx, actor, true) }()
			// Release only after the heartbeat is waiting on the changed row.
			// Its statement began with the old version visible to its snapshot.
			deadline := time.Now().Add(time.Second)
			for {
				var waiting bool
				if err = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database() AND wait_event_type='Lock'
					AND (query LIKE '%UPDATE supivpn.nodes%' OR query LIKE '%supivpn.agent_heartbeat(%'))`).Scan(&waiting); err != nil {
					t.Fatal("cannot observe waiting test heartbeat")
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("heartbeat did not wait for concurrent node change")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if change.expireWhileWaiting {
				for {
					var expired bool
					if err = pool.QueryRow(ctx, "SELECT lease_expires_at<=clock_timestamp() FROM supivpn.nodes WHERE node_id=$1", actor.NodeID).Scan(&expired); err != nil {
						t.Fatal("cannot observe test lease expiry")
					}
					if expired {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("test lease did not expire")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			if err = lock.Commit(ctx); err != nil {
				t.Fatal("cannot commit node change")
			}
			if err = <-completed; !errors.Is(err, postgres.ErrGeneration) {
				t.Fatal("heartbeat renewed a stale, expired or fenced generation")
			}
			var healthy *time.Time
			if err = pool.QueryRow(ctx, "SELECT healthy_since FROM supivpn.nodes WHERE node_id=$1", actor.NodeID).Scan(&healthy); err != nil || healthy != nil {
				t.Fatal("rejected heartbeat changed witness health")
			}
		})
	}
}
