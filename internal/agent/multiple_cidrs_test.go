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

func expandedGroupConfig() config {
 c := groupConfig()
 c.GroupPools[1].CIDR = ""
 c.GroupPools[1].CIDRs = []string{"10.203.0.0/30", "10.203.0.128/30"}
 return c
}

func TestMultipleGroupCIDRsValidation(t *testing.T) {
 for _, tc := range []struct {
  name string
  change func(*config)
 }{
  {"both-fields", func(c *config) { c.GroupPools[1].CIDR = "10.203.0.0/30" }},
  {"empty", func(c *config) { c.GroupPools[1].CIDRs = nil }},
  {"duplicate", func(c *config) { c.GroupPools[1].CIDRs[1] = c.GroupPools[1].CIDRs[0] }},
  {"overlap", func(c *config) { c.GroupPools[1].CIDRs[1] = "10.203.0.0/29" }},
  {"other-group-overlap", func(c *config) { c.GroupPools[1].CIDRs[1] = c.GroupPools[0].CIDR }},
  {"outside-network", func(c *config) { c.GroupPools[1].CIDRs[1] = "10.254.252.128/30" }},
  {"malformed", func(c *config) { c.GroupPools[1].CIDRs[1] = "invalid" }},
  {"noncanonical", func(c *config) { c.GroupPools[1].CIDRs[1] = "10.203.0.129/30" }},
  {"ipv6", func(c *config) { c.GroupPools[1].CIDRs[1] = "fd00::/64" }},
  {"too-small", func(c *config) { c.GroupPools[1].CIDRs[1] = "10.203.0.128/31" }},
  {"too-many", func(c *config) { c.GroupPools[1].CIDRs = make([]string, 33) }},
 } {
  t.Run(tc.name, func(t *testing.T) {
   c := expandedGroupConfig()
   if err := validateAuthorization(c); err != nil { t.Fatal(err) }
   tc.change(&c)
   if validateAuthorization(c) == nil { t.Fatal("invalid group ranges accepted") }
  })
 }
}

func TestMultipleGroupCIDRsExhaustionAndRelease(t *testing.T) {
 c := expandedGroupConfig()
 if err := validateAuthorization(c); err != nil { t.Fatal(err) }
 p := newPoolAllocator(c)
 for i, want := range []string{"10.203.0.2", "10.203.0.129", "10.203.0.130"} {
  cid := uint64(i + 1)
  ip, err := p.acquire(cid, coreGroup)
  if err != nil || ip.String() != want { t.Fatalf("lease %d = %s, %v; want %s", cid, ip, err, want) }
  again, err := p.acquire(cid, coreGroup)
  if err != nil || again != ip { t.Fatal("retry changed lease") }
 }
 if _, err := p.acquire(4, coreGroup); !errors.Is(err, errPoolFull) { t.Fatalf("full group: %v", err) }
 if len(p.leases) != 3 { t.Fatal("exhaustion created a lease in another group") }
 if _, err := p.acquire(1, devGroup); err == nil { t.Fatal("connection changed group") }
 p.release(2)
 ip, err := p.acquire(4, coreGroup)
 if err != nil || ip.String() != "10.203.0.129" { t.Fatal("secondary pool address was not reusable") }
 p.release(1)
 ip, err = p.acquire(5, coreGroup)
 if err != nil || ip.String() != "10.203.0.2" { t.Fatal("primary pool free address was skipped") }
}

func TestSAMLUsesAdditionalCIDRWithinSelectedGroup(t *testing.T) {
 signer, md := testIdP(t)
 a, commands := testApp(t, md)
 a.config = expandedGroupConfig()
 a.pools = newPoolAllocator(a.config)
 if _, err := a.pools.acquire(99, coreGroup); err != nil { t.Fatal(err) }
 body := responseBody(t, a, signer, groupAssertionFor(a, devGroup, coreGroup), true, false)
 if w := submit(a, body, "test-browser"); w.Code != http.StatusOK { t.Fatalf("login: %d", w.Code) }
 if cmd := <-commands; cmd != "client-auth 7 2\nifconfig-push 10.203.0.129 255.255.255.0\nEND" {
  t.Fatalf("wrong authorization: %s", cmd)
 }
 a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
 if _, exists := a.pools.owners[netip.MustParseAddr("10.203.0.129")]; exists { t.Fatal("disconnected secondary lease retained") }
}

func TestThreeNodeAdditionalRangesHaveDisjointLeases(t *testing.T) {
 all := make(map[netip.Addr]bool)
 for node := 0; node < 3; node++ {
  c := groupConfig()
  c.VPNNetwork = "10.200.0.0/20"
  c.GroupPools = []groupPool{
   {GroupName: coreGroup, Priority: 10, CIDRs: []string{fmt.Sprintf("10.200.0.%d/26", node*64), fmt.Sprintf("10.200.10.%d/26", node*64)}},
   {GroupName: devGroup, Priority: 20, CIDRs: []string{fmt.Sprintf("10.200.2.%d/26", node*64)}},
  }
  if err := validateAuthorization(c); err != nil { t.Fatal(err) }
  p := newPoolAllocator(c)
  for _, group := range c.GroupPools {
   count := 0
   for cid := uint64(len(p.leases)+1); ; cid++ {
    ip, err := p.acquire(cid, group.GroupName)
    if errors.Is(err, errPoolFull) { break }
    if err != nil { t.Fatal(err) }
    if all[ip] { t.Fatalf("IP %s shared between nodes or groups", ip) }
    all[ip] = true
    count++
    if count > 124 { t.Fatal("allocation escaped group ranges") }
   }
   want := 62 * len(group.CIDRs)
   if node == 0 && group.GroupName == coreGroup { want-- }
   if count != want { t.Fatalf("node %d group %s: %d leases, want %d", node, group.GroupName, count, want) }
  }
 }
 // The fourth slot is reserved and must not be allocated by the three nodes.
 for ip := range all {
  if ip.As4()[3] >= 192 { t.Fatalf("reserved slot used: %s", ip) }
 }
}
