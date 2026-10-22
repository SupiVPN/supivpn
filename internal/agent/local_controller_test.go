// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"supivpn/internal/agentclient"
	"supivpn/internal/vm"
)

// Exercise the actual startup path, private listener and durable journal without
// loading AWS credentials. HTTP failure must not activate in-memory login.
func TestLocalControllerStartupAndRecovery(t *testing.T) {
	dir, err := os.MkdirTemp("", "supi-local-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	listener, err := vm.ListenAgent(socket, uint32(os.Geteuid()), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	current := ""
	var mu sync.Mutex
	heartbeatAllowed := true
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "" {
			t.Error("local startup attempted AWS authentication")
		}
		var q agentclient.Request
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error("invalid request")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/agent/v1/rotate":
			if q.Generation != current && q.Previous != current {
				w.WriteHeader(409)
				return
			}
			current = q.Generation
		case "/agent/v1/heartbeat":
			if q.Generation != current || !heartbeatAllowed {
				w.WriteHeader(409)
				return
			}
		default:
			t.Error("unexpected startup operation")
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Config.ConnContext = vm.AgentContext
	server.Start()
	defer server.Close()
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://vpn.example.test")
	newNode := func() *agent {
		c := groupConfig()
		c.RemoteController = localControllerConfig()
		c.RemoteController.AgentSocket, c.RemoteController.StateDirectory = socket, state
		return newAgent(c, origin)
	}
	a := newNode()
	cleanup, err := a.startRemote(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := a.remote.generation
	if first == "" || !a.now().Before(a.remote.leaseUntil) {
		t.Fatal("startup did not establish a lease")
	}
	second := newNode()
	if close, err := second.startRemote(context.Background()); err == nil {
		close()
		t.Fatal("second process acquired same generation journal")
	}
	cleanup()
	cleanup, err = second.startRemote(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.remote.generation == first {
		t.Fatal("restart reused old generation")
	}
	cleanup()
	// A committed CAS with a lost local checkpoint must be recovered and then
	// rotated again, never reused as a live process generation.
	journalPath := filepath.Join(state, "generation.json")
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var journal map[string]string
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	interrupted := journal["current"]
	journal["current"], journal["next"] = first, interrupted
	data, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	third := newNode()
	cleanup, err = third.startRemote(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.remote.generation == interrupted || third.remote.generation == first {
		t.Fatal("interrupted generation was reused")
	}
	cleanup()
	// Do not publish a partially initialized remote client when the lease fails.
	mu.Lock()
	heartbeatAllowed = false
	mu.Unlock()
	failed := newNode()
	if close, err := failed.startRemote(context.Background()); err == nil {
		close()
		t.Fatal("started without lease")
	}
	if failed.remote != nil {
		t.Fatal("failed startup retained a usable remote client")
	}
	// Bind the saved state to the server UID as well as the path. This must
	// fail before connecting even if that other UID is currently absent.
	wrong := newNode()
	uid := uint32(os.Geteuid()) + 1
	wrong.config.RemoteController.ControllerUID = &uid
	if close, err := wrong.startRemote(context.Background()); err == nil {
		close()
		t.Fatal("journal accepted a different controller identity")
	}
	server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	missing := newNode()
	if close, err := missing.startRemote(ctx); err == nil {
		close()
		t.Fatal("missing controller accepted")
	}
	if missing.remote != nil {
		t.Fatal("missing controller activated local fallback")
	}
}
