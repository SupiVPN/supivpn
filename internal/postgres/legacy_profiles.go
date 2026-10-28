// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import "errors"

// ValidateLegacyProfileNodes validates the temporary, explicit migration policy.
// Node identities come from the authenticated adapter, never from request JSON.
func ValidateLegacyProfileNodes(nodes []string) error {
	if len(nodes) > 256 {
		return errors.New("too many legacy profile nodes")
	}
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		if !validName(node) || seen[node] {
			return errors.New("legacy_profile_nodes requires distinct valid node IDs")
		}
		seen[node] = true
	}
	return nil
}

// WithLegacyProfiles returns an independently configured store. Configure it
// before serving requests; no request or shared mutable slice can enable legacy.
// Remove this compatibility path in v0.10.0, after the 0.8/0.9 transition window.
func (s *Store) WithLegacyProfiles(nodes []string) (*Store, error) {
	if err := ValidateLegacyProfileNodes(nodes); err != nil {
		return nil, err
	}
	if s == nil || s.component == Recovery && len(nodes) != 0 {
		return nil, errors.New("legacy profile policy requires an authentication component")
	}
	copy := *s
	copy.legacyProfileNodes = make(map[string]bool, len(nodes))
	for _, node := range nodes {
		copy.legacyProfileNodes[node] = true
	}
	return &copy, nil
}

func (s *Store) LegacyProfilesAllowed(node string) bool {
	return s != nil && s.legacyProfileNodes[node]
}
