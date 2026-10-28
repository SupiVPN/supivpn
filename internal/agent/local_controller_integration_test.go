// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controlruntime"
	"supivpn/internal/postgres"
)

func TestLocalControllerPostgresLifecycle(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal("cannot reset disposable database")
	}
	app := &controlruntime.Application{Public: http.NotFoundHandler(), Agents: agentapi.New(postgres.New(pool), 180*time.Second)}
	server := serveRuntimeVM(t, app)
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://vpn.example.test")
	start := func() (*agent, func()) {
		t.Helper()
		c := groupConfig()
		c.ProfileBinding = "required"
		c.RemoteController = localControllerConfig()
		c.RemoteController.NodeID = "runtime-node"
		c.RemoteController.AgentSocket, c.RemoteController.StateDirectory = server.socket, state
		node := newAgent(c, origin)
		close, err := node.startRemote(ctx)
		if err != nil {
			t.Fatal("local agent startup failed", err)
		}
		return node, close
	}
	first, closeFirst := start()
	defer closeFirst()
	old := first.remote.generation
	cid, kid := int64(7), int64(2)
	proof := ownedFixtureProof(t, postgres.New(pool), sha256.Sum256([]byte("synthetic owner")), t.Name())
	request := agentclient.Request{Generation: old, CID: &cid, KID: &kid, Ticket: strings.Repeat("a", 43), ProfileID: proof.ID, ProfileSecret: proof.Secret}
	if _, err := first.remote.api.Call(ctx, "register", request); err != nil {
		t.Fatal("registration failed", err)
	}
	// Replacing the controller must not rotate the still-running node or lose
	// its pending login. The same client reconnects and authenticates the peer.
	server.stop()
	server = serveRuntimeVMAt(t, app, server.socket)
	if _, err := first.remote.api.Call(ctx, "heartbeat", agentclient.Request{Generation: old}); err != nil {
		t.Fatal("controller restart lost the lease", err)
	}
	request.Ticket = ""
	request.ProfileID, request.ProfileSecret = "", ""
	if decision, err := first.remote.api.Call(ctx, "fetch", request); err != nil || decision != nil {
		t.Fatal("controller restart lost the pending login")
	}
	// Model a stopped agent/OpenVPN pair before rotating its durable journal.
	closeFirst()
	second, closeSecond := start()
	defer closeSecond()
	if second.remote.generation == old {
		t.Fatal("node restart reused its generation")
	}
	if _, err := second.remote.api.Call(ctx, "heartbeat", agentclient.Request{Generation: old}); agentclient.Status(err) != 409 {
		t.Fatal("old generation remained usable")
	}
	if _, err := second.remote.api.Call(ctx, "fetch", request); agentclient.Status(err) != 410 {
		t.Fatal("old login remained usable")
	}
	// Advance only the disposable fixture's lease. An expired database lease
	// must close management even if the agent's local timer has not elapsed.
	if _, err := pool.Exec(ctx, "UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE node_id='runtime-node'"); err != nil {
		t.Fatal("cannot advance test lease")
	}
	m, _ := fakeManagement(t)
	second.attach(m)
	second.remote.heartbeatDue = time.Time{}
	second.remoteStep(ctx)
	select {
	case <-m.done:
	default:
		t.Fatal("expired controller lease left management open")
	}
	closeSecond()
	// Local recovery uses a fresh authenticated generation after the pair has
	// stopped; it does not need EC2 fencing or direct database cleanup.
	third, closeThird := start()
	defer closeThird()
	if third.remote.generation == second.remote.generation || !third.now().Before(third.remote.leaseUntil) {
		t.Fatal("restart did not establish a fresh local lease")
	}
}
