// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import "testing"

func TestRemovedLegacyProfileConfiguration(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{`{}`, true}, {`{"legacy_profile_nodes":[]}`, false},
		{`{"legacy_profile_nodes":null}`, false},
		{`{"legacy_profile_nodes":["old-node"]}`, false},
		{`{"legacy_profile_nodes":["*"]}`, false},
		{`{"legacy_profile_nodes":["old-node","old-node"]}`, false},
		{`{"legacy_profile_nodes":"old-node"}`, false},
	} {
		if _, err := ParseConfig(tc.raw); (err == nil) != tc.valid {
			t.Fatal("legacy configuration validation", err)
		}
	}
}
