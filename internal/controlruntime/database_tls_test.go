// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"encoding/json"
	"testing"

	"supivpn/internal/postgres"
)

func TestControllerDatabaseTLSConfiguration(t *testing.T) {
	for _, tc := range []struct {
		options *postgres.TLSConfig
		ok      bool
	}{
		{nil, true}, {&postgres.TLSConfig{}, true},
		{&postgres.TLSConfig{Mode: "require"}, true},
		{&postgres.TLSConfig{Mode: "verify-full", CAFile: "/opt/db-ca.pem", ServerName: "writer.example.test"}, true},
		{&postgres.TLSConfig{Mode: "verify-full"}, true},
		{&postgres.TLSConfig{Mode: "require", ServerName: "writer.example.test"}, false},
		{&postgres.TLSConfig{Mode: "verify-full", CAFile: "relative.pem"}, false},
		{&postgres.TLSConfig{Mode: "prefer"}, false},
	} {
		c := validConfig()
		c.DatabaseTLS = tc.options
		body, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ParseConfig(string(body))
		if (err == nil) != tc.ok {
			t.Fatal("incorrect controller TLS validation")
		}
		if tc.ok && tc.options != nil && (decoded.DatabaseTLS == nil || *decoded.DatabaseTLS != *tc.options) {
			t.Fatal("TLS settings lost during decode")
		}
		if _, _, err := c.Policy(); (err == nil) != tc.ok {
			t.Fatal("programmatic controller bypassed TLS validation")
		}
	}
	if _, err := ParseConfig(`{"database_tls":{"mode":"verify-full","unknown":true}}`); err == nil {
		t.Fatal("unknown TLS option accepted")
	}
}
