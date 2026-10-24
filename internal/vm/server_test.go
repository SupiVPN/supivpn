// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package vm

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/postgres"
)

type identityStore struct{ nodes chan string }

func TestAdditionalAgentExplicitIdentity(t *testing.T) {
	uid := uint32(0)
	c := Config{Listen: "127.0.0.1:8443", AgentUID: &uid, NodeID: "legacy",
		AgentSocket: "/run/controller/legacy.sock", TLSCertificate: "/etc/test.crt",
		TLSChain: "/etc/test-chain.crt", TLSPrivateKey: "/etc/test.key"}
	good := AgentEndpoint{Socket: "/run/controller/bound.sock", UID: &uid, NodeID: "bound"}
	c.AdditionalAgents = []AgentEndpoint{good}
	if err := c.Validate(); err != nil {
		t.Fatal("explicit second identity refused", err)
	}
	for _, bad := range []AgentEndpoint{
		{Socket: good.Socket, NodeID: good.NodeID},
		{Socket: good.Socket, UID: &uid, NodeID: c.NodeID},
		{Socket: c.AgentSocket, UID: &uid, NodeID: good.NodeID},
	} {
		c.AdditionalAgents = []AgentEndpoint{bad}
		if c.Validate() == nil {
			t.Fatal("ambiguous second identity accepted")
		}
	}
}

func TestTwoPrivateAgentIdentities(t *testing.T) {
	dir, err := os.MkdirTemp("", "supi-two-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	nodes := make(chan string, 2)
	var locals []net.Listener
	for _, name := range []string{"legacy", "bound"} {
		l, e := ListenAgent(filepath.Join(dir, name), uint32(os.Geteuid()), name)
		if e != nil {
			t.Fatal(e)
		}
		locals = append(locals, l)
		defer l.Close()
	}
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveListeners(ctx, web, locals, http.NotFoundHandler(), agentapi.New(&identityStore{nodes: nodes}, time.Minute))
	}()
	for _, name := range []string{"legacy", "bound"} {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, name))
		}}
		client := &http.Client{Transport: tr, Timeout: time.Second}
		r, _ := http.NewRequest("POST", "http://controller/agent/v1/rotate", strings.NewReader(`{"generation":"g1"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Node-ID", "forged")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal("private request failed")
		}
		response.Body.Close()
		tr.CloseIdleConnections()
		if response.StatusCode != 204 {
			t.Fatal("private request refused")
		}
		select {
		case got := <-nodes:
			if got != name {
				t.Fatal("node identity crossed listeners")
			}
		case <-time.After(time.Second):
			t.Fatal("missing actor")
		}
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("shutdown blocked")
	}
}

func (s *identityStore) Heartbeat(_ context.Context, a postgres.Agent) error {
	s.nodes <- a.NodeID
	return nil
}

func (s *identityStore) RotateNode(_ context.Context, node, prev, next string) error {
	s.nodes <- node
	return nil
}
func (*identityStore) Register(context.Context, postgres.Agent, postgres.Connection, string, time.Duration) error {
	panic("unused")
}
func (*identityStore) Fetch(context.Context, postgres.Agent, postgres.Connection) (postgres.Decision, error) {
	panic("unused")
}
func (*identityStore) Acknowledge(context.Context, postgres.Agent, string, postgres.Outcome) error {
	panic("unused")
}
func (*identityStore) Cancel(context.Context, postgres.Agent, postgres.Connection) error {
	panic("unused")
}

func TestPrivateSocketIdentityAndControllerRestart(t *testing.T) {
	// The repository path can itself exceed macOS' Unix socket limit. Use a
	// short path in the user's approved temporary directory for these listeners.
	dir, err := os.MkdirTemp("", "supivpn-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0700)
	socket := filepath.Join(dir, "agent.sock")
	nodes := make(chan string, 4)
	api := agentapi.New(&identityStore{nodes: nodes}, time.Minute)
	management, peer := net.Pipe()
	defer management.Close()
	defer peer.Close()
	for i := 0; i < 2; i++ {
		local, err := ListenAgent(socket, uint32(os.Geteuid()), "node-a")
		if err != nil {
			t.Fatal(err)
		}
		web, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			local.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- ServeListeners(ctx, web, local, http.NotFoundHandler(), api) }()
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		req, _ := http.NewRequest("POST", "http://controller/agent/v1/rotate", strings.NewReader(`{"generation":"g1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", "node-b")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatal("Unix request failed")
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 204 {
			cancel()
			t.Fatalf("Unix identity refused: %d", resp.StatusCode)
		}
		select {
		case node := <-nodes:
			if node != "node-a" {
				t.Error("trusted request header")
			}
		case <-time.After(time.Second):
			t.Error("no identity from kernel")
		}
		// The public listener does not expose the agent API.
		resp, err = http.Post("http://"+web.Addr().String()+"/agent/v1/rotate", "application/json", strings.NewReader(`{"generation":"g1"}`))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Error("agent API exposed on public listener")
		}
		transport.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("controller shutdown blocked")
		}
		// A controller owns no agent/OpenVPN management connection.
		management.SetDeadline(time.Now().Add(time.Second))
		peer.SetDeadline(time.Now().Add(time.Second))
		sent := make(chan error, 1)
		go func() { _, e := peer.Write([]byte("alive")); sent <- e }()
		b := make([]byte, 5)
		if _, err = io.ReadFull(management, b); err != nil {
			t.Fatal("controller shutdown closed separate management connection")
		}
		if err = <-sent; err != nil {
			t.Fatal(err)
		}
	}
}
func TestSocketRejectsWrongUIDAndUnsafePaths(t *testing.T) {
	dir, err := os.MkdirTemp("", "supivpn-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0700)
	socket := filepath.Join(dir, "agent.sock")
	os.Chmod(dir, 0755)
	if l, err := ListenAgent(socket, uint32(os.Geteuid()), "node-a"); err == nil {
		l.Close()
		t.Fatal("nonprivate parent accepted")
	}
	os.Chmod(dir, 0700)
	sentinel := []byte("existing-file")
	if err = os.WriteFile(socket, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := ListenAgent(socket, uint32(os.Geteuid()), "node-a"); err == nil {
		l.Close()
		t.Fatal("existing path replaced")
	}
	data, _ := os.ReadFile(socket)
	if string(data) != string(sentinel) {
		t.Fatal("existing file changed")
	}
	os.Remove(socket)
	l, err := ListenAgent(socket, uint32(os.Geteuid())+1, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			c.Close()
			t.Error("wrong UID accepted")
		}
	}()
	c, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = c.Read(b[:]); err == nil {
		t.Error("wrong UID connection stayed usable")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Error("wrong UID not rejected promptly")
	}
	l.Close()
	<-done
}
