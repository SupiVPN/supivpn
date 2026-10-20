// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package tracecontext

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCanonicalTraceIDs(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef"
	for _, bad := range []string{"", strings.Repeat("0", 32), strings.ToUpper(valid), valid[:31], valid + "0", valid[:31] + "g", valid[:31] + "\n", "00-" + valid + "-0123456789abcdef-01"} {
		if ValidID(bad) || ID(WithID(WithID(context.Background(), valid), bad)) != "" {
			t.Fatal("invalid ID accepted or inherited")
		}
	}
	if !ValidID(valid) || ID(WithID(nil, valid)) != valid || ID(nil) != "" {
		t.Fatal("invalid context contract")
	}
	parent := WithID(context.Background(), valid)
	seen := map[string]bool{valid: true}
	for range 1000 {
		id := ID(New(parent))
		if !ValidID(id) || seen[id] {
			t.Fatal("request reused a trace ID")
		}
		seen[id] = true
	}
	if ID(parent) != valid {
		t.Fatal("parent context mutated")
	}
}

func TestLoginTraceReconstruction(t *testing.T) {
	ticket := "synthetic-login-ticket-for-correlation-tests-only"
	hash := sha256.Sum256([]byte(ticket))
	id := ForLogin(ticket)
	if !ValidID(id) || id != ForLoginHash(hash[:]) || id == hex.EncodeToString(hash[:16]) {
		t.Fatal("trace does not safely reconstruct across stores")
	}
	if id == ForLogin(ticket+"2") || id == ForLogin("profile_"+ticket) {
		t.Fatal("distinct flows share a trace")
	}
	if ForLogin("") != "" || ForLogin(strings.Repeat("x", 129)) != "" || ForLoginHash(nil) != "" || ForLoginHash(hash[:31]) != "" {
		t.Fatal("malformed material accepted")
	}
	// This public fixture pins the cross-version derivation; never change its
	// domain without an explicit correlation compatibility plan.
	if id != "eea51fe908d8e94e6dffc2411ebb05ea" {
		t.Fatal("cross-version trace derivation changed")
	}
}
