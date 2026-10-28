// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"testing"
)

func TestLegacyProfileConfiguration(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{`{}`, true}, {`{"legacy_profile_nodes":[]}`, true},
		{`{"legacy_profile_nodes":["old-node"]}`, true},
		{`{"legacy_profile_nodes":["*"]}`, false},
		{`{"legacy_profile_nodes":["old-node","old-node"]}`, false},
		{`{"legacy_profile_nodes":"old-node"}`, false},
	} {
		if _, err := ParseConfig(tc.raw); (err == nil) != tc.valid {
			t.Fatal("legacy configuration validation", err)
		}
	}
	// Programmatic callers cannot bypass ParseConfig or reach the database with
	// an invalid migration policy, including the isolated agent Lambda path.
	c := Config{LegacyProfileNodes: []string{"*"}}
	if _, _, err := c.Policy(); err == nil {
		t.Fatal("invalid public policy")
	}
	if _, err := OpenAgent(context.Background(), c, "", nil); err == nil {
		t.Fatal("invalid agent policy")
	}
}
