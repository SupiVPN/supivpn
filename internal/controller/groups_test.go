// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"errors"
	"testing"

	"supivpn/internal/saml"
)

const (
	coreGroup = "admins-vpn"
	devGroup  = "engineers-production-vpn"
)

func testGroups() []Group {
	return []Group{{GroupName: devGroup, Priority: 20}, {GroupName: coreGroup, Priority: 10}}
}

func TestGroupSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members map[string]bool
		want    string
		err     error
	}{
		{"both", map[string]bool{coreGroup: true, devGroup: true}, coreGroup, nil},
		{"dev", map[string]bool{devGroup: true}, devGroup, nil},
		{"neither", map[string]bool{coreGroup: false, devGroup: false}, "", ErrNoGroup},
		{"empty", nil, "", ErrNoGroup},
		{"unrelated", map[string]bool{devGroup: true, "unknown": true}, devGroup, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group, err := selectGroup(testGroups(), tc.members)
			if !errors.Is(err, tc.err) || group.GroupName != tc.want {
				t.Fatalf("unexpected selection: %s %v", group.GroupName, err)
			}
		})
	}
}

func TestGroupClaimValueLimit(t *testing.T) {
	for _, count := range []int{0, 1, 1024, 1025} {
		values := make([]saml.AttributeValue, count)
		for i := range values {
			values[i] = saml.AttributeValue{Type: "xs:string", Value: devGroup}
		}
		assertion := &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{{
			Name: "groups", NameFormat: groupAttributeFormat, Values: values,
		}}}}}
		members, err := assertionGroups(assertion, "groups")
		if count == 0 || count > 1024 {
			if !errors.Is(err, errGroupsClaim) || len(members) != 0 {
				t.Fatalf("accepted %d group values", count)
			}
		} else if err != nil || len(members) != 1 || !members[devGroup] {
			t.Fatalf("failed to read/deduplicate %d group values", count)
		}
	}
}
