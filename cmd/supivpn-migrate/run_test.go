// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"supivpn/internal/postgres"
)

func TestStaleMigrationBinaryRejectedBeforeConfiguration(t *testing.T) {
	err := run(context.Background(), "does-not-exist.json", strings.Repeat("0", 64), "")
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatal("stale binary reached configuration/database setup")
	}
	err = run(context.Background(), "does-not-exist.json", postgres.MigrationDigest(), "")
	if err == nil || !strings.Contains(err.Error(), "configuration unavailable") {
		t.Fatal("matching binary did not proceed to configuration")
	}
}

func TestMigrationConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.json")
	valid := `{"region":"eu-central-1","host":"db.example.test","port":"5432","database":"supivpn","secret_arn":"arn:aws:secretsmanager:eu-central-1:123456789012:secret:test"}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(path)
	if err != nil || c.Database != "supivpn" {
		t.Fatal("valid non-secret config rejected")
	}
	for _, input := range []string{
		valid + "{}",
		strings.Replace(valid, "db.example.test", "host?sslmode=disable", 1),
		strings.Replace(valid, `"port":"5432"`, `"port":"0"`, 1),
		strings.Replace(valid, `"region":"eu-central-1"`, `"region":"us-east-1"`, 1),
		strings.TrimSuffix(valid, "}") + `,"password":"test-only"}`,
		strings.Repeat("x", 17000),
	} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfig(path); err == nil || strings.Contains(err.Error(), "test-only") {
			t.Fatal("invalid/secret-bearing configuration accepted or echoed")
		}
	}
	if err := run(context.Background(), path, "", "test-only-dsn"); err == nil ||
		!strings.Contains(err.Error(), "either") || strings.Contains(err.Error(), "test-only") {
		t.Fatal("ambiguous credential sources accepted or echoed")
	}
}

func TestDatabaseWaitRecoveryAndFailure(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := awaitDatabase(ctx, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded connection attempt")
		}
		calls++
		if calls < 3 {
			return errors.New("temporary test-only credential failure")
		}
		return nil
	}, time.Millisecond)
	if err != nil || calls != 3 {
		t.Fatal("connection readiness did not recover")
	}
	cancel()
	err = awaitDatabase(ctx, func(context.Context) error {
		return errors.New("test-only-sensitive-upstream-error")
	}, time.Millisecond)
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("timeout failed open or exposed the upstream error")
	}
}

func TestMigrationTLSConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.json")
	base := `{"region":"eu-central-1","host":"alias.example.test","port":"5432","database":"supivpn","secret_arn":"arn:aws:secretsmanager:eu-central-1:123456789012:secret:test","database_tls":`
	for _, tc := range []struct {
		block string
		ok    bool
	}{
		{`{}`, true},
		{`{"mode":"require"}`, true},
		{`{"mode":"verify-full","ca_file":"/etc/supivpn/db-ca.pem","server_name":"writer.example.test"}`, true},
		{`{"mode":"verify-full"}`, true},
		{`{"mode":"require","server_name":"writer.example.test"}`, false},
		{`{"mode":"disable"}`, false},
		{`{"mode":"verify-full","ca_file":"relative.pem"}`, false},
		{`{"mode":"verify-full","unknown":true}`, false},
	} {
		if os.WriteFile(path, []byte(base+tc.block+"}"), 0600) != nil {
			t.Fatal("write configuration fixture")
		}
		c, err := readConfig(path)
		if (err == nil) != tc.ok {
			t.Fatal("incorrect migration TLS validation")
		}
		if tc.ok && c.DatabaseTLS == nil {
			t.Fatal("TLS settings lost during decode")
		}
		if !tc.ok {
			if err := run(context.Background(), path, "", ""); err == nil {
				t.Fatal("invalid TLS reached migration execution")
			}
		}
	}
}
