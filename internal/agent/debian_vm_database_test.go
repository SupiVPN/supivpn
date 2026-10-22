// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration && linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const vmDBFixtures = "/opt/supivpn-test/database"

func vmRemoteDatabase() bool {
	return os.Getenv("SUPIVPN_TEST_VM_DATABASE") == "remote"
}

func vmNoLocalDatabase(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/usr/lib/postgresql/18/bin/postgres", "/etc/postgresql/18/supivpn"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("remote setup installed or configured a local database")
		}
	}
}

func vmDatabaseQuery(t *testing.T, query string) string {
	t.Helper()
	if !vmRemoteDatabase() {
		return vmCommand(t, "runuser", "-u", "postgres", "--", "psql", "-X", "-h", "/var/run/postgresql",
			"-p", "55433", "-d", "supivpn_test", "-Atc", query)
	}
	password, err := os.ReadFile(filepath.Join(vmDBFixtures, "runtime.password"))
	if err != nil {
		t.Fatal("missing disposable database fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "psql", "-X", "-w", "-Atc", query)
	command.Env = []string{"PATH=/usr/bin:/bin", "PGHOST=db.supivpn.test", "PGPORT=5432",
		"PGDATABASE=supivpn_test", "PGUSER=supivpn_runtime", "PGPASSWORD=" + string(password),
		"PGSSLMODE=verify-full", "PGSSLROOTCERT=" + filepath.Join(vmDBFixtures, "ca.pem"), "PGCONNECT_TIMEOUT=5"}
	out, err := command.Output()
	if err != nil {
		t.Fatal("remote database verification failed (output withheld)")
	}
	return strings.TrimSpace(string(out))
}

func vmConfigureRemoteDatabase(t *testing.T, setup map[string]any, setupPath string) {
	t.Helper()
	vmNoLocalDatabase(t)
	db := map[string]any{
		"host": "db.supivpn.test", "port": 5432,
		"ca_file":                 filepath.Join(vmDBFixtures, "ca.pem"),
		"runtime_password_file":   filepath.Join(vmDBFixtures, "runtime.password"),
		"migration_password_file": filepath.Join(vmDBFixtures, "migration.password"),
	}
	setup["database"] = db
	password, err := os.ReadFile(db["runtime_password_file"].(string))
	if err != nil {
		t.Fatal("missing disposable password")
	}
	wrongPassword := filepath.Join(vmDBFixtures, "wrong.password")
	vmWrite(t, wrongPassword, append(password, '!'), 0600, "")
	for _, check := range []struct{ field, value string }{
		{"host", "10.0.2.2"},
		{"ca_file", "/etc/ssl/certs/ca-certificates.crt"},
		{"runtime_password_file", wrongPassword},
	} {
		original := db[check.field]
		db[check.field] = check.value
		vmSaveJSON(t, setupPath, setup, 0600, "")
		if exec.Command("supivpn-setup", "init", "--config", setupPath).Run() == nil {
			t.Fatal("remote setup accepted invalid", check.field)
		}
		if _, err := os.Stat("/etc/supivpn"); !os.IsNotExist(err) {
			t.Fatal("remote preflight rejection left partial configuration")
		}
		db[check.field] = original
	}
	t.Log("remote preflight rejected wrong hostname, CA and password before host writes")
}

func vmCheckRemoteDatabase(t *testing.T) {
	t.Helper()
	vmNoLocalDatabase(t)
	if vmDatabaseQuery(t, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()") != "t" {
		t.Fatal("remote connection does not use TLS")
	}
	config := vmJSON(t, "/etc/supivpn/controller/controller.json")
	tls, ok := config["database_tls"].(map[string]any)
	if !ok || tls["mode"] != "verify-full" || tls["server_name"] != "db.supivpn.test" {
		t.Fatal("installed controller does not verify the database identity")
	}
}

func vmDependency(t *testing.T, name string, start bool) {
	t.Helper()
	if name != "external-database" {
		action := "stop"
		if start {
			action = "start"
		}
		vmCommand(t, "systemctl", action, name)
		return
	}
	// Isolate only PostgreSQL from this disposable guest; SSH and VPN stay up.
	// TCP resets also interrupt existing pooled connections. Restore is idempotent.
	const table = "supivpn_vm_database"
	if start {
		if exec.Command("nft", "list", "table", "ip", table).Run() == nil {
			vmCommand(t, "nft", "delete", "table", "ip", table)
		}
		return
	}
	vmCommand(t, "nft", "add", "table", "ip", table)
	vmCommand(t, "nft", "add", "chain", "ip", table, "output", "{ type filter hook output priority 0; policy accept; }")
	vmCommand(t, "nft", "add", "rule", "ip", table, "output", "ip", "daddr", "10.0.2.2",
		"tcp", "dport", "5432", "reject", "with", "tcp", "reset")
}
