// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"supivpn/internal/postgres"
)

// Exercises restricted runtime grants and the credential hook on the disposable DB.
func TestRuntimeDatabaseRoleAndCredentialReconnect(t *testing.T) {
	admin, _ := integrationDatabase(t)
	ctx := context.Background()
	sql, err := os.ReadFile("../postgres/testdata/runtime-role.sql")
	if err != nil {
		t.Fatal("runtime bootstrap missing")
	}
	if _, err = admin.Exec(ctx, string(sql)); err != nil {
		t.Fatal("runtime role bootstrap failed")
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP OWNED BY supivpn_runtime; DROP ROLE supivpn_runtime"); err != nil {
			t.Error("runtime role cleanup failed")
		}
	}()
	u, _ := url.Parse(os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
	u.User = url.User("supivpn_runtime")
	var calls atomic.Int32
	var unavailable atomic.Bool
	pool, err := postgres.OpenWithPassword(ctx, u.String(), func(context.Context) (string, error) {
		calls.Add(1)
		if unavailable.Load() {
			return "", errors.New("test credential service unavailable")
		}
		return "test-only-password", nil
	})
	if err != nil {
		t.Fatal("runtime pool failed")
	}
	defer pool.Close()
	store := postgres.New(pool)
	if !store.Ready(ctx) {
		t.Fatal("runtime role cannot read schema readiness")
	}
	if err = store.RotateNode(ctx, "credential-test-node", "", "g1"); err != nil {
		t.Fatal("runtime node write denied")
	}
	if err = registerOwnedFixture(t, store, ctx, postgres.Agent{NodeID: "credential-test-node", Generation: "g1"}, postgres.Connection{CID: 1, KID: 1}, strings.Repeat("c", 43), time.Minute, [32]byte{1}); err != nil {
		t.Fatal("runtime login/identity sequence write denied")
	}
	if _, err = store.Prune(ctx, 10); err != nil {
		t.Fatal("runtime cleanup denied")
	}
	if _, err = pool.Exec(ctx, "CREATE TABLE supivpn.must_not_create (id integer)"); err == nil {
		t.Fatal("runtime role has DDL permissions")
	}
	before := calls.Load()
	pool.Reset()
	if !store.Ready(ctx) || calls.Load() <= before {
		t.Fatal("reconnect did not obtain fresh credentials")
	}
	unavailable.Store(true)
	pool.Reset()
	check, cancel := context.WithTimeout(ctx, time.Second)
	if store.Ready(check) {
		t.Error("credential failure did not fail closed")
	}
	cancel()
	unavailable.Store(false)
	if !store.Ready(ctx) {
		t.Fatal("pool failed to recover after credential service returned")
	}
}
