// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func unixPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "supi-unix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

func unixServer(t *testing.T, path string, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Listener.Close()
	s.Listener = listener
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestUnixClientRequestsAndControllerRestart(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyCalls.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var q Request
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Generation != "g1" || r.Method != "POST" || r.URL.Path != "/agent/v1/heartbeat" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" || r.Header.Get("X-Node-ID") != "" {
			t.Error("incorrect Unix request or unexpected credentials")
		}
		w.WriteHeader(204)
	})
	path := unixPath(t)
	server := unixServer(t, path, handler)
	client, err := NewUnix(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	call := func() error {
		_, err := client.Call(context.Background(), "heartbeat", Request{Generation: "g1"})
		return err
	}
	if err := call(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := call(); err == nil || Status(err) != 0 || strings.Contains(err.Error(), path) {
		t.Fatal("missing controller did not fail safely")
	}
	unixServer(t, path, handler)
	if err := call(); err != nil {
		t.Fatal("client did not reconnect to restarted controller", err)
	}
	if calls.Load() != 2 || proxyCalls.Load() != 0 {
		t.Fatal("request escaped Unix transport or was lost")
	}
}

func TestUnixClientRejectsUnsafePathsAndIdentity(t *testing.T) {
	for _, path := range []string{"", "relative.sock", "/", "/run/a/../b.sock", "/run//agent.sock", "/run/agent.sock\n", "/run/agent\x00.sock"} {
		if client, err := NewUnix(path, 0); err == nil {
			client.Close()
			t.Fatal("invalid socket path accepted")
		}
	}
	for _, name := range []string{"socket-mode", "directory-mode", "wrong-uid", "socket-symlink", "directory-symlink", "regular-file"} {
		t.Run(name, func(t *testing.T) {
			path := unixPath(t)
			var calls atomic.Int32
			unixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			uid := uint32(os.Geteuid())
			switch name {
			case "socket-mode":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "wrong-uid":
				uid++
			case "socket-symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "directory-symlink":
				link := filepath.Join(filepath.Dir(path), "link")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "agent.sock")
			case "regular-file":
				path += ".file"
				if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			client, err := NewUnix(path, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err = client.Call(context.Background(), "heartbeat", Request{Generation: "g1"}); err == nil || Status(err) != 0 || calls.Load() != 0 {
				t.Fatal("unsafe local peer received an API request")
			}
		})
	}
}

func TestUnixClientRedirectAndCancellation(t *testing.T) {
	var escaped atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer target.Close()
	path := unixPath(t)
	unixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	client, err := NewUnix(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Call(context.Background(), "rotate", Request{Generation: "g1"}); Status(err) != 307 || escaped.Load() != 0 {
		t.Fatal("Unix request followed a redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Call(ctx, "heartbeat", Request{Generation: "g1"}); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	stalled := unixPath(t)
	release := make(chan struct{})
	defer close(release)
	unixServer(t, stalled, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	bounded, err := NewUnix(stalled, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer bounded.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := bounded.Call(ctx, "heartbeat", Request{Generation: "g1"}); err == nil || time.Since(started) > time.Second {
		t.Fatal("Unix request ignored cancellation")
	}
}
