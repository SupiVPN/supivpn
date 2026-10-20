// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
    "errors"
    "fmt"
    "net/http"
    "net/netip"
    "testing"
)

// Same aggregate on both TUN interfaces; only group allocation ranges differ.
func clusterGroupConfig(node int) config {
    names := []string{"admins-vpn", "ops-production-vpn", "engineers-production-vpn", "staff-production-vpn", "testers-production-vpn",
        "ops-vpn", "engineers-vpn", "staff-vpn", "testers-vpn", "helpdesk-vpn"}
    c := config{SAMLGroupsAttribute: "groups", VPNNetwork: "10.200.0.0/20", PendingSeconds: 180, SessionSeconds: 900}
    for i, name := range names {
        c.GroupPools = append(c.GroupPools, groupPool{GroupName: name, Priority: (i + 1) * 10,
            CIDR: fmt.Sprintf("10.200.%d.%d/25", i, node * 128)})
    }
    return c
}

func TestClusterGroupAddressRanges(t *testing.T) {
    seen := make(map[netip.Addr]bool)
    for node := range 2 {
        c := clusterGroupConfig(node)
        if err := validateAuthorization(c); err != nil { t.Fatal(err) }
        pools := newPoolAllocator(c)
        if pools.netmask() != "255.255.240.0" { t.Fatal("client must receive the aggregate mask") }
        for groupIndex, group := range c.GroupPools {
            count := 126
            if node == 0 && groupIndex == 0 { count-- } // Local gateway 10.200.0.1.
            prefix := netip.MustParsePrefix(group.CIDR)
            for lease := 0; lease < count; lease++ {
                cid := uint64(groupIndex * 1024 + lease)
                ip, err := pools.acquire(cid, group.GroupName)
                if err != nil || seen[ip] || !prefix.Contains(ip) || ip.String() == "10.200.0.1" {
                    t.Fatalf("node %d group %s: invalid/duplicate lease %s: %v", node, group.GroupName, ip, err)
                }
                seen[ip] = true
            }
            if _, err := pools.acquire(uint64(groupIndex * 1024 + count), group.GroupName); !errors.Is(err, errPoolFull) {
                t.Fatal("exhausted group must not spill into another group or node")
            }
        }
    }
}

func TestSignedClusterGroupPriorities(t *testing.T) {
    signer, md := testIdP(t)
    for _, tc := range []struct {
        name string
        groups []string
        octet int
    }{
        {"admins-first", []string{"helpdesk-vpn", "ops-production-vpn", "admins-vpn"}, 0},
        {"prod-before-other", []string{"ops-vpn", "testers-production-vpn"}, 4},
        {"prod-order", []string{"staff-production-vpn", "engineers-production-vpn", "ops-production-vpn"}, 1},
        {"other-order", []string{"helpdesk-vpn", "engineers-vpn"}, 6},
        {"engineers-production", []string{"engineers-production-vpn"}, 2},
    } {
        t.Run(tc.name, func(t *testing.T) {
            for node := range 2 {
                a, commands := testApp(t, md)
                a.config = clusterGroupConfig(node)
                a.pools = newPoolAllocator(a.config)
                assertion := groupAssertionFor(a, tc.groups...)
                body := responseBody(t, a, signer, assertion, true, false)
                if submit(a, body, "test-browser").Code != http.StatusOK { t.Fatal("signed membership refused") }
                first := node * 128 + 1
                if node == 0 && tc.octet == 0 { first++ }
                expected := fmt.Sprintf("client-auth 7 2\nifconfig-push 10.200.%d.%d 255.255.240.0\nEND", tc.octet, first)
                if command := <-commands; command != expected { t.Fatalf("wrong group/node allocation: %s", command) }
            }
        })
    }
}
