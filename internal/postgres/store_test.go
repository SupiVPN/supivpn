// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"supivpn/internal/controller"
)

func TestPoolTLSAndLimits(t *testing.T) {
	t.Setenv("PGPASSFILE", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("PGSERVICE", "")
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{"", false},
		{"host=db.example.test user=test dbname=supivpn sslmode=disable", false},
		{"host=db.example.test user=test dbname=supivpn sslmode=require", true},
		{"host=db.example.test user=test dbname=supivpn sslmode=verify-ca", true},
		{"host=db.example.test user=test dbname=supivpn sslmode=verify-full", true},
		{"host=127.0.0.1 user=test dbname=supivpn_test sslmode=disable", true},
		{"host=localhost user=test dbname=supivpn_test sslmode=disable", false},
		{"host=db.example.test user=test dbname=supivpn sslmode=prefer", false},
		{"host=db.example.test user=test dbname=supivpn sslmode=allow", false},
	} {
		c, err := poolConfig(tc.dsn)
		if (err == nil) != tc.ok {
			t.Fatalf("unexpected TLS policy result for case %+v", tc.ok)
		}
		if err == nil && (c.MaxConns != 4 || c.MinConns != 0 || c.MaxConnIdleTime != time.Minute ||
			c.ConnConfig.ConnectTimeout != 5*time.Second || c.ConnConfig.RuntimeParams["lock_timeout"] != "2000") {
			t.Fatal("database connection budget or timeouts changed")
		}
	}
	c, err := poolConfig("host=db.example.test user=test dbname=supivpn sslmode=require")
	if err != nil || c.ConnConfig.TLSConfig == nil || !c.ConnConfig.TLSConfig.InsecureSkipVerify ||
		c.ConnConfig.TLSConfig.MinVersion != tls.VersionTLS12 || len(c.ConnConfig.Fallbacks) != 0 {
		t.Fatal("require must use TLS without certificate verification or plaintext fallback")
	}
	if c.PrepareConn == nil || c.ConnConfig.ValidateConnect == nil || c.MinIdleConns != 0 {
		t.Fatal("reconnect/writer checks not configured")
	}
}

func TestOpenDoesNotRequireAvailableDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := Open(ctx, "host=127.0.0.1 port=1 user=test dbname=supivpn_test sslmode=disable")
	if err != nil {
		t.Fatal("unavailable database prevented pool creation")
	}
	defer p.Close()
	if New(p).Ready(ctx) {
		t.Fatal("unavailable database reported ready")
	}
}
func TestDecisionTimePrecision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	d := controller.Authorization{NotBefore: now.Add(123 * time.Nanosecond),
		NotOnOrAfter:       now.Add(time.Minute + 456*time.Nanosecond),
		SessionExpiresAt:   now.Add(15*time.Minute + 789*time.Nanosecond),
		AssertionExpiresAt: now.Add(time.Minute + 456*time.Nanosecond)}
	rounded := normalizeDecision(d)
	if rounded.NotBefore.Before(d.NotBefore) || rounded.NotOnOrAfter.After(d.NotOnOrAfter) ||
		rounded.SessionExpiresAt.After(d.SessionExpiresAt) || rounded.AssertionExpiresAt.After(d.AssertionExpiresAt) {
		t.Fatal("PostgreSQL precision widened authorization bounds")
	}
	if rounded.NotBefore.Nanosecond()%1000 != 0 || rounded.NotOnOrAfter.Nanosecond()%1000 != 0 {
		t.Fatal("timestamps not normalized")
	}
}
func TestDecisionValidation(t *testing.T) {
	now := time.Now().UTC()
	base := controller.Authorization{SubjectHash: sha256.Sum256([]byte("test-user")), MaxConnections: 1, GroupName: "admins-vpn", AssertionHash: sha256.Sum256([]byte("test assertion")),
		NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute),
		SessionExpiresAt: now.Add(15 * time.Minute), AssertionExpiresAt: now.Add(time.Minute)}
	if !validDecision(base, now) {
		t.Fatal("valid decision rejected")
	}
	for _, mutate := range []func(*controller.Authorization){
		func(d *controller.Authorization) { d.GroupName = "" },
		func(d *controller.Authorization) { d.AssertionHash = [32]byte{} },
		func(d *controller.Authorization) { d.NotBefore = now.Add(time.Second) },
		func(d *controller.Authorization) { d.NotOnOrAfter = now },
		func(d *controller.Authorization) { d.SessionExpiresAt = time.Time{} },
        func(d *controller.Authorization) { d.SessionUnlimited = true },
		func(d *controller.Authorization) { d.AssertionExpiresAt = now },
		func(d *controller.Authorization) { d.DenialReason = "no_vpn_group" },
	} {
		d := base
		mutate(&d)
		if validDecision(d, now) {
			t.Fatal("invalid decision accepted")
		}
	}
	base.GroupName = ""
	base.DenialReason = "no_vpn_group"
	if !validDecision(base, now) {
		t.Fatal("denial rejected")
	}
}
func TestDatabaseErrorsAreOpaque(t *testing.T) {
	if publicError(errors.New("private driver detail")) != controller.ErrUnavailable {
		t.Fatal("driver error leaked")
	}
	if publicError(ErrConflict) != ErrConflict {
		t.Fatal("domain error lost")
	}
}
