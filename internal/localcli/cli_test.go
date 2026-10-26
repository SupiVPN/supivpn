// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package localcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testID = "svp1_0123456789abcdef0123456789abcdef"

func TestRejectAmbiguousOrRemoteCommands(t *testing.T) {
	for _, args := range [][]string{
		{}, {"profiles", "delete", testID}, {"profiles", "block", testID, "--revision", "1"},
		{"profiles", "block", testID, "--revision", "0", "--yes"},
		{"profiles", "block", testID, "--revision", "1", "--revision", "2", "--yes"},
		{"profiles", "activate", testID, "--revision", "1", "--yes", "--yes"},
		{"profiles", "list", "--limit", "1000000"}, {"profiles", "list", "--after", "bad"},
		{"profiles", "status", testID, "--yes"}, {"profiles", "status", ";rm"},
		{"status", "--host", "evil"}, {"status", "--instance", "../controller"},
		{"status", "--instance", "x.service --host=evil"}, {"status", "--config", "/tmp/evil"},
		{"sessions", "drop", "--user", "alice"}, {"sessions", "drop", "--user", "alice\nclient-kill 2", "--yes"},
		{"sessions", "status", "--user", " alice"}, {"sessions", "status", "--user", ""},
	} {
		called := false
		err := execute(context.Background(), args, &bytes.Buffer{}, func(string) error { called = true; return nil }, nil)
		if err == nil || called {
			t.Fatal("invalid command reached host or process")
		}
	}
}

func TestProfileCommandsUseRestrictedServiceAndPrivateStdin(t *testing.T) {
	for _, action := range []string{"block", "activate", "status", "list"} {
		args := []string{"profiles", action}
		if action != "list" {
			args = append(args, testID)
		}
		if action == "block" || action == "activate" {
			args = append(args, "--revision", "7", "--yes")
		}
		r, err := parse(args)
		if err != nil {
			t.Fatal(err)
		}
		c := operationCommand(r)
		all := strings.Join(c.args, " ")
		if c.path != "/usr/bin/systemd-run" || strings.Contains(all, testID) ||
			!strings.Contains(all, "User=supivpn-controller") ||
			!strings.Contains(all, "NoNewPrivileges=yes") ||
			!strings.Contains(all, "ProtectSystem=strict") ||
			!strings.Contains(all, "RuntimeMaxSec=20s") ||
			!strings.Contains(all, "EnvironmentFile=/etc/supivpn/controller/database.env") {
			t.Fatal("privilege boundary changed")
		}
		var q map[string]any
		if json.Unmarshal(c.input, &q) != nil || q["action"] != "profile-"+action || q["source"] != "supivpn.operator.v1" {
			t.Fatal("missing operator envelope")
		}
	}
}

func TestResultsDoNotForwardUnknownOrSecretFields(t *testing.T) {
	var out bytes.Buffer
	err := execute(context.Background(), []string{"profiles", "status", testID}, &out, func(string) error { return nil },
		func(context.Context, command) ([]byte, error) {
			return []byte(`{"ok":true,"secret":"do-not-forward","state":{"profile":{"profile_id":"` + testID + `","state":"active","revision":1,"created_at":"2026-01-01T00:00:00Z","secret_hash":"do-not-forward"}}}`), nil
		})
	if err != nil || strings.Contains(out.String(), "do-not-forward") || !strings.Contains(out.String(), testID) {
		t.Fatal("response filtering failed")
	}
	out.Reset()
	err = execute(context.Background(), []string{"profiles", "status", testID}, &out, func(string) error { return nil },
		func(context.Context, command) ([]byte, error) {
			return []byte("secret diagnostic"), errors.New("secret connection string")
		})
	if err == nil || strings.Contains(err.Error(), "secret") || out.Len() != 0 {
		t.Fatal("error leaked subprocess output")
	}
}

func TestSessionsAreLocalAndTargeted(t *testing.T) {
	r, err := parse([]string{"sessions", "drop", "--user", "Alice", "--instance", "bound", "--yes"})
	if err != nil {
		t.Fatal(err)
	}
	c := operationCommand(r)
	if c.path != "/usr/sbin/supivpn" || strings.Join(c.args, " ") != "-config /etc/supivpn/nodes/bound/agent.json -operator-request" {
		t.Fatal("remote session transport")
	}
	if strings.Contains(strings.Join(c.args, " "), "Alice") || !bytes.Contains(c.input, []byte("Alice")) {
		t.Fatal("username not kept on stdin")
	}
}

func TestProfileOwnerLabelIsEscapedAuditOutput(t *testing.T) {
	for _, action := range []string{"status", "list"} {
		args := []string{"profiles", action}
		if action == "status" {
			args = append(args, testID)
		}
		owner := "verified\nowner\u001b[31m@example.test"
		p := map[string]any{"profile_id": testID, "state": "active", "revision": 1, "owner_username": owner, "subject_hash": "not-for-output", "secret_hash": "not-for-output"}
		state := map[string]any{"profile": p, "profiles": []any{p}}
		raw, _ := json.Marshal(map[string]any{"ok": true, "state": state})
		var out bytes.Buffer
		err := execute(context.Background(), args, &out, func(string) error { return nil }, func(context.Context, command) ([]byte, error) { return raw, nil })
		if err != nil || strings.Contains(out.String(), "not-for-output") || strings.Contains(out.String(), owner) || !strings.Contains(out.String(), `"owner_username"`) {
			t.Fatal("unsafe or missing owner output")
		}
		var decoded map[string]any
		if json.Unmarshal(out.Bytes(), &decoded) != nil {
			t.Fatal("invalid JSON")
		}
	}
}

func TestHostRejectionPreventsAllOperations(t *testing.T) {
	called := false
	err := execute(context.Background(), []string{"profiles", "block", testID, "--revision", "1", "--yes"}, &bytes.Buffer{},
		func(string) error { return errors.New("unsafe host") },
		func(context.Context, command) ([]byte, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatal("unsafe installation reached privileged operation")
	}
}

func TestBoundedSubprocessAndEnvironment(t *testing.T) {
	var b boundedOutput
	if _, err := b.Write(make([]byte, 65537)); err == nil || b.Len() != 0 {
		t.Fatal("unbounded reply")
	}
	t.Setenv("PGPASSWORD", "synthetic-not-inherited")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "synthetic-not-inherited")
	t.Setenv("PAGER", "synthetic-not-inherited")
	raw, err := runCommand(context.Background(), command{path: "/usr/bin/env"})
	if err != nil || bytes.Contains(raw, []byte("synthetic-not-inherited")) || bytes.Contains(raw, []byte("HOME=")) {
		t.Fatal("caller environment propagated")
	}
}

func TestUnsafeConfigurationPaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if os.WriteFile(p, []byte("{}"), 0666) != nil {
		t.Fatal("fixture write")
	}
	if safeFile(p) == nil {
		t.Fatal("untrusted configuration accepted")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(p, link) != nil {
		t.Fatal("fixture link")
	}
	if safeFile(link) == nil {
		t.Fatal("symlink accepted")
	}
}
