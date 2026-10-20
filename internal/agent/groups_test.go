// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"supivpn/internal/saml"
)

const (
	// Group names are matched exactly, including case.
	coreGroup      = "admins-vpn"
	devGroup       = "engineers-production-vpn"
	unrelatedGroup = "unrelated-vpn"
)

func groupConfig() config {
	return config{SAMLGroupsAttribute: "groups",
		VPNNetwork: "10.203.0.0/24", PendingSeconds: 180, SessionSeconds: 900,
		GroupPools: []groupPool{
			{GroupName: devGroup, Priority: 20, CIDR: "10.203.0.64/26"},
			{GroupName: coreGroup, Priority: 10, CIDR: "10.203.0.0/26"},
		}}
}

func TestAuthorizationConfiguration(t *testing.T) {
	for _, name := range []string{"valid", "overlap", "outside", "host-bits", "ipv6", "public", "tiny", "duplicate-priority", "duplicate-name", "negative-priority", "no-groups", "no-attribute", "allowlist-fallback", "bad-attribute", "empty-name", "name-space", "name-slash", "long-name"} {
		t.Run(name, func(t *testing.T) {
			c := groupConfig()
			switch name {
			case "overlap":
				c.GroupPools[0].CIDR = "10.203.0.32/27"
			case "outside":
				c.GroupPools[0].CIDR = "10.254.254.0/26"
			case "host-bits":
				c.GroupPools[0].CIDR = "10.203.0.65/26"
			case "ipv6":
				c.GroupPools[0].CIDR = "fd00::/64"
			case "public":
				c.VPNNetwork = "192.0.2.0/24"
			case "tiny":
				c.GroupPools[0].CIDR = "10.203.0.64/31"
			case "duplicate-priority":
				c.GroupPools[0].Priority = 10
			case "duplicate-name":
				c.GroupPools[0].GroupName = coreGroup
			case "negative-priority":
				c.GroupPools[0].Priority = -1
			case "no-groups":
				c.GroupPools = nil
			case "no-attribute":
				c.SAMLGroupsAttribute = ""
			case "allowlist-fallback":
				c.AllowedSubjects = []string{"test-user"}
			case "bad-attribute":
				c.SAMLGroupsAttribute = " groups"
			case "empty-name":
				c.GroupPools[0].GroupName = ""
			case "name-space":
				c.GroupPools[0].GroupName = "dev prod vpn"
			case "name-slash":
				c.GroupPools[0].GroupName = "dev/prod"
			case "long-name":
				c.GroupPools[0].GroupName = strings.Repeat("a", 129)
			}
			if err := validateAuthorization(c); (err == nil) != (name == "valid") {
				t.Fatalf("unexpected validation: %v", err)
			}
		})
	}
}

func TestPoolAllocationAndRelease(t *testing.T) {
	p := newPoolAllocator(groupConfig())
	seen := map[netip.Addr]bool{}
	for cid := uint64(0); cid < 61; cid++ {
		ip, err := p.acquire(cid, coreGroup)
		if err != nil || seen[ip] || ip == netip.MustParseAddr("10.203.0.1") || !netip.MustParsePrefix("10.203.0.0/26").Contains(ip) {
			t.Fatalf("invalid or reused lease: %s %v", ip, err)
		}
		seen[ip] = true
		if again, err := p.acquire(cid, coreGroup); err != nil || again != ip {
			t.Fatal("lease changed on reauth")
		}
	}
	if _, err := p.acquire(100, coreGroup); !errors.Is(err, errPoolFull) {
		t.Fatal("full pool accepted client")
	}
	if _, err := p.acquire(0, devGroup); err == nil {
		t.Fatal("connection changed groups")
	}
	p.release(0)
	ip, err := p.acquire(100, coreGroup)
	if err != nil || ip.String() != "10.203.0.2" {
		t.Fatal("released address not reusable")
	}
	dev, err := p.acquire(101, devGroup)
	if err != nil || dev.String() != "10.203.0.65" || p.netmask() != "255.255.255.0" {
		t.Fatal("wrong group pool or node netmask")
	}
}

func TestConcurrentDevicesHaveDistinctLeases(t *testing.T) {
	a := &agent{pools: newPoolAllocator(groupConfig())}
	addresses := make(chan netip.Addr, maxConnections)
	var wg sync.WaitGroup
	for cid := uint64(0); cid < maxConnections; cid++ {
		wg.Add(1)
		go func(cid uint64) {
			defer wg.Done()
			a.mu.Lock()
			ip, err := a.pools.acquire(cid, coreGroup)
			a.mu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
			addresses <- ip
		}(cid)
	}
	wg.Wait()
	close(addresses)
	seen := map[netip.Addr]bool{}
	for ip := range addresses {
		if seen[ip] {
			t.Fatal("simultaneous connections share an IP")
		}
		seen[ip] = true
	}
	if len(seen) != maxConnections {
		t.Fatal("missing leases")
	}
}

func TestLearnAddressEnforcesAssignedSource(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		assigned string
		want     bool
	}{
		{[]string{"add", "10.203.0.65", ""}, "10.203.0.65", true},
		{[]string{"update", "10.203.0.65", "untrusted-cn"}, "10.203.0.65", true},
		{[]string{"update", "10.203.0.2", "untrusted-cn"}, "10.203.0.65", false},
		{[]string{"add", "10.203.0.65"}, "", false},
		{[]string{"add", "10.203.0.64/26"}, "10.203.0.65", false},
		{[]string{"add", "fd00::1"}, "fd00::1", false},
		{[]string{"delete", "10.203.0.65"}, "", true},
		{[]string{"unknown", "10.203.0.65"}, "10.203.0.65", false},
		{[]string{"add"}, "10.203.0.65", false},
	} {
		if got := allowLearnedAddress(tc.args, tc.assigned); got != tc.want {
			t.Fatalf("unexpected hook decision for %v", tc.args)
		}
	}
}

func enableTestGroups(a *testApplication) {
	a.config = groupConfig()
	a.pools = newPoolAllocator(a.config)
}

func groupAssertionFor(a *testApplication, ids ...string) *saml.Assertion {
	assertion := assertionFor(a)
	attribute := saml.Attribute{Name: a.config.SAMLGroupsAttribute, NameFormat: groupAttributeFormat}
	for _, id := range ids {
		attribute.Values = append(attribute.Values, saml.AttributeValue{Type: "xs:string", Value: id})
	}
	assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: []saml.Attribute{attribute}}}
	return assertion
}

func TestGroupSAMLAuthorizationAndLeaseLifecycle(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	enableTestGroups(a)
	assertion := groupAssertionFor(a, devGroup, coreGroup)
	assertion.Subject.NameID.Value = "group-member-outside-old-allowlist"
	body := responseBody(t, a, signer, assertion, true, false)
	if w := submit(a, body, "test-browser"); w.Code != http.StatusOK {
		t.Fatalf("group login: %d", w.Code)
	}
	if cmd := <-commands; cmd != "client-auth 7 2\nifconfig-push 10.203.0.2 255.255.255.0\nEND" {
		t.Fatalf("wrong authorization: %s", cmd)
	}
	c := a.connections[7]
	expires, address := c.expires, c.address
	a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3})
	if cmd := <-commands; cmd != "client-auth-nt 7 3" {
		t.Fatal("reauth failed")
	}
	if c.address != address || c.expires != expires {
		t.Fatal("reauth changed lease or session deadline")
	}
	if submit(a, body, "test-browser").Code == http.StatusOK {
		t.Fatal("replay accepted")
	}
	a.now = func() time.Time { return expires.Add(time.Second) }
	a.expire()
	if cmd := <-commands; cmd != "client-kill 7" {
		t.Fatal("expired session not killed")
	}
	if _, reserved := a.pools.owners[address]; !reserved {
		t.Fatal("lease released before disconnect")
	}
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	if len(a.pools.owners) != 0 || len(a.connections) != 0 {
		t.Fatal("disconnected lease not freed")
	}
}

func TestSignedGroupClaims(t *testing.T) {
	signer, md := testIdP(t)
	for _, tc := range []struct {
		name string
		ids  []string
		want string
	}{
		{"dev-only", []string{devGroup}, "10.203.0.65"},
		{"both", []string{devGroup, coreGroup}, "10.203.0.2"},
		{"reversed", []string{coreGroup, devGroup}, "10.203.0.2"},
		{"duplicate-values", []string{devGroup, devGroup}, "10.203.0.65"},
		{"unrelated-group", []string{unrelatedGroup, devGroup}, "10.203.0.65"},
		{"custom-attribute", []string{devGroup}, "10.203.0.65"},
		{"omitted-format", []string{devGroup}, "10.203.0.65"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, commands := testApp(t, md)
			enableTestGroups(a)
			if tc.name == "custom-attribute" {
				a.config.SAMLGroupsAttribute = "Role"
			}
			assertion := groupAssertionFor(a, tc.ids...)
			if tc.name == "omitted-format" {
				assertion.AttributeStatements[0].Attributes[0].NameFormat = ""
			}
			body := responseBody(t, a, signer, assertion, true, false)
			if submit(a, body, "test-browser").Code != http.StatusOK {
				t.Fatal("valid signed groups refused")
			}
			if cmd := <-commands; cmd != "client-auth 7 2\nifconfig-push "+tc.want+" 255.255.255.0\nEND" {
				t.Fatal("wrong pool selected")
			}
		})
	}
}

func TestGroupAuthorizationFailures(t *testing.T) {
	signer, md := testIdP(t)
	for _, name := range []string{"none", "missing", "empty", "blank-value", "malformed", "csv", "whitespace",
		"wrong-name", "friendly-name-only", "wrong-format", "duplicate-attribute", "duplicate-statement",
		"nested-nameid", "full", "uninitialized-pool", "form-groups", "uuid-value", "opaque-id", "case-sensitive-name", "name-prefix", "control-character"} {
		t.Run(name, func(t *testing.T) {
			a, commands := testApp(t, md)
			enableTestGroups(a)
			assertion := groupAssertionFor(a, devGroup, coreGroup)
			attribute := &assertion.AttributeStatements[0].Attributes[0]
			switch name {
			case "none":
				attribute.Values = []saml.AttributeValue{{Type: "xs:string", Value: unrelatedGroup}}
			case "missing", "form-groups":
				assertion.AttributeStatements = nil
			case "empty":
				attribute.Values = nil
			case "blank-value":
				attribute.Values[0].Value = ""
			case "malformed":
				attribute.Values[0].Value = "dev/prod"
			case "uuid-value":
				attribute.Values = []saml.AttributeValue{{Type: "xs:string", Value: "11111111-1111-1111-1111-111111111111"}}
			case "opaque-id":
				attribute.Values = []saml.AttributeValue{{Type: "xs:string", Value: "00g11111111111111111"}}
			case "case-sensitive-name":
				attribute.Values = []saml.AttributeValue{{Type: "xs:string", Value: strings.ToUpper(devGroup)}}
			case "name-prefix":
				attribute.Values = []saml.AttributeValue{{Type: "xs:string", Value: devGroup + "-extra"}}
			case "control-character":
				attribute.Values[0].Value = devGroup + "\n"
			case "csv":
				attribute.Values[0].Value = devGroup + "," + coreGroup
			case "whitespace":
				attribute.Values[0].Value = " " + devGroup
			case "wrong-name":
				attribute.Name = "Groups"
			case "friendly-name-only":
				attribute.Name = "other"
				attribute.FriendlyName = "groups"
			case "wrong-format":
				attribute.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
			case "duplicate-attribute":
				assertion.AttributeStatements[0].Attributes = append(assertion.AttributeStatements[0].Attributes, *attribute)
			case "duplicate-statement":
				assertion.AttributeStatements = append(assertion.AttributeStatements, assertion.AttributeStatements[0])
			case "nested-nameid":
				attribute.Values[0].NameID = &saml.NameID{Value: devGroup}
			case "full":
				a.config.GroupPools[1].CIDR = "10.203.0.0/30"
				a.pools = newPoolAllocator(a.config)
				if _, err := a.pools.acquire(99, coreGroup); err != nil {
					t.Fatal(err)
				}
			case "uninitialized-pool":
				a.pools = nil
			}
			body := responseBody(t, a, signer, assertion, true, false)
			if name == "form-groups" {
				body += "&groups=" + coreGroup
			}
			if submit(a, body, "test-browser").Code != http.StatusForbidden {
				t.Fatal("group rejection bypassed")
			}
			// submit waits for the management ACK, so the fake has already queued
			// the command. Fail immediately instead of hanging if it is missing.
			select {
			case cmd := <-commands:
				if !strings.HasPrefix(cmd, "client-deny 7 2 ") {
					t.Fatal("pending client not denied")
				}
			default:
				t.Fatal("pending client not denied")
			}
			if a.pools != nil {
				if _, allocated := a.pools.leases[7]; allocated {
					t.Fatal("rejected login received an IP (or lower-priority fallback)")
				}
			}
			if submit(a, body, "test-browser").Code == http.StatusOK {
				t.Fatal("denied assertion became reusable")
			}
		})
	}
}

func TestOversizedSignedGroupClaimRejected(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	enableTestGroups(a)
	ids := make([]string, 1025)
	for i := range ids {
		ids[i] = devGroup
	}
	body := responseBody(t, a, signer, groupAssertionFor(a, ids...), true, false)
	if submit(a, body, "test-browser").Code != http.StatusForbidden || a.connections[7].active || len(a.pools.leases) != 0 {
		t.Fatal("oversized assertion authorized a connection")
	}
	// The SAML library may reject this before group authorization. In that
	// case there is no management command; a valid denial must never authorize.
	for len(commands) > 0 {
		if cmd := <-commands; !strings.HasPrefix(cmd, "client-deny 7 2 ") {
			t.Fatal("unexpected management command")
		}
	}
}

func TestUntrustedGroupClaims(t *testing.T) {
	signer, md := testIdP(t)
	for _, name := range []string{"unsigned", "tampered-group"} {
		t.Run(name, func(t *testing.T) {
			a, commands := testApp(t, md)
			enableTestGroups(a)
			body := responseBody(t, a, signer, groupAssertionFor(a, devGroup), name != "unsigned", false)
			if name == "tampered-group" {
				form, err := url.ParseQuery(body)
				if err != nil {
					t.Fatal(err)
				}
				xml, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
				if err != nil {
					t.Fatal(err)
				}
				changed := strings.ReplaceAll(string(xml), devGroup, coreGroup)
				if changed == string(xml) {
					t.Fatal("test did not change the signed group")
				}
				form.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(changed)))
				body = form.Encode()
			}
			if submit(a, body, "test-browser").Code != http.StatusForbidden || len(commands) != 0 || len(a.pools.leases) != 0 {
				t.Fatal("unsigned or tampered groups authorized")
			}
		})
	}
}

func TestDisconnectBeforeGroupCallback(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	enableTestGroups(a)
	body := responseBody(t, a, signer, groupAssertionFor(a, coreGroup), true, false)
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	if submit(a, body, "test-browser").Code == http.StatusOK || len(commands) != 0 || len(a.pools.leases) != 0 {
		t.Fatal("disconnected client authorized")
	}
}

func TestConcurrentGroupRedemption(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	enableTestGroups(a)
	body := responseBody(t, a, signer, groupAssertionFor(a, devGroup, coreGroup), true, false)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- submit(a, body, "test-browser").Code }()
	}
	wg.Wait()
	close(statuses)
	success := 0
	for code := range statuses {
		if code == http.StatusOK {
			success++
		}
	}
	if success != 1 || len(commands) != 1 || len(a.pools.leases) != 1 {
		t.Fatal("concurrent callback allocated or authorized twice")
	}
}
