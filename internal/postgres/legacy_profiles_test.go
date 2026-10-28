// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"strings"
	"testing"
)

func TestLegacyPolicyIsExplicitAndImmutable(t *testing.T) {
	base := New(nil)
	nodes := []string{"migration-node"}
	legacy, err := base.WithLegacyProfiles(nodes)
	if err != nil {
		t.Fatal(err)
	}
	nodes[0] = "bound-node"
	if base.LegacyProfilesAllowed("migration-node") || !legacy.LegacyProfilesAllowed("migration-node") || legacy.LegacyProfilesAllowed("bound-node") {
		t.Fatal("legacy policy was implicit or mutated through caller memory")
	}
	revoked, err := legacy.WithLegacyProfiles(nil)
	if err != nil || revoked.LegacyProfilesAllowed("migration-node") || !legacy.LegacyProfilesAllowed("migration-node") {
		t.Fatal("policy replacement modified an existing store")
	}
	for _, bad := range [][]string{{""}, {"*"}, {"node", "node"}, {"node\n"}, {strings.Repeat("n", 129)}, make([]string, 257)} {
		if _, err := base.WithLegacyProfiles(bad); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
