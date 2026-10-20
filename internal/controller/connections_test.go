// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"testing"
)

func TestConnectionLimitPolicy(t *testing.T) {
	p := Policy{SAMLGroupsAttribute: "groups", Groups: []Group{
		{GroupName: "admins-vpn", Priority: 10, MaxConnectionsPerUser: 2},
		{GroupName: "engineers-vpn", Priority: 20},
	}}
	if ValidatePolicy(p) != nil || p.ConnectionLimit("engineers-vpn") != 1 || p.ConnectionLimit("admins-vpn") != 2 {
		t.Fatal("default or group override lost")
	}
	g, err := selectGroup(p.Groups, map[string]bool{"admins-vpn": true, "engineers-vpn": true})
	if err != nil || p.ConnectionLimit(g.GroupName) != 2 {
		t.Fatal("limit must follow the selected group, not add membership limits")
	}
	p.MaxConnectionsPerUser = 3
	if p.ConnectionLimit("engineers-vpn") != 3 || p.ConnectionLimit("admins-vpn") != 2 { t.Fatal("inheritance changed") }
	for _, n := range []int{-1, 17} {
		p.MaxConnectionsPerUser = n
		if ValidatePolicy(p) == nil { t.Fatal("invalid default accepted") }
		p.MaxConnectionsPerUser = 1
		p.Groups[0].MaxConnectionsPerUser = n
		if ValidatePolicy(p) == nil { t.Fatal("invalid group override accepted") }
		p.Groups[0].MaxConnectionsPerUser = 2
	}
}
