// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"net"
	"net/netip"

	"supivpn/internal/controller"
)

type groupPool struct {
	SessionSeconds        *int     `json:"session_seconds,omitempty"`
	MaxConnectionsPerUser int      `json:"max_connections_per_user,omitempty"`
	GroupName             string   `json:"group_name"`
	Priority              int      `json:"priority"`
	CIDR                  string   `json:"cidr,omitempty"`
	CIDRs                 []string `json:"cidrs,omitempty"`
}

func (g groupPool) ranges() []string {
	if g.CIDR != "" {
		return []string{g.CIDR}
	}
	return g.CIDRs
}

var (
	errNoGroup  = controller.ErrNoGroup
	errPoolFull = errors.New("selected VPN group pool is full")
)

func privatePrefix(value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p != p.Masked() || p.Bits() < 16 || p.Bits() > 30 {
		return netip.Prefix{}, errors.New("VPN CIDRs must be canonical private IPv4 networks, /16 through /30")
	}
	return p, nil
}

func validateAuthorization(c config) error {
	if err := controller.ValidatePolicy(controllerPolicy(c)); err != nil {
		return err
	}
	if c.SAMLGroupsAttribute == "" {
		if c.VPNNetwork != "" {
			return errors.New("allowlist mode requires no group network configuration")
		}
		return nil
	}
	network, err := privatePrefix(c.VPNNetwork)
	if err != nil {
		return err
	}
	if network.Bits() > 29 {
		return errors.New("node VPN network must be /29 or larger")
	}
	var prefixes []netip.Prefix
	for _, group := range c.GroupPools {
		if (group.CIDR != "" && group.CIDRs != nil) || len(group.ranges()) == 0 || len(group.ranges()) > 32 {
			return errors.New("each VPN group requires either cidr or 1..32 cidrs")
		}
		for _, cidr := range group.ranges() {
			prefix, err := privatePrefix(cidr)
			if err != nil {
				return err
			}
			if prefix.Bits() < network.Bits() || !network.Contains(prefix.Addr()) {
				return errors.New("every group pool must fit inside this node's VPN network")
			}
			for _, other := range prefixes {
				if prefix.Overlaps(other) {
					return errors.New("VPN group pools must not overlap")
				}
			}
			prefixes = append(prefixes, prefix)
		}
	}
	return nil
}

type poolLease struct {
	address   netip.Addr
	groupName string
}

// Access is serialized by agent.mu. Leases belong to a connection, not a username:
// simultaneous devices must not receive the same address.
type poolAllocator struct {
	dual     bool
	network  netip.Prefix
	prefixes map[string][]netip.Prefix
	leases   map[uint64]poolLease
	owners   map[netip.Addr]uint64
}

func newPoolAllocator(c config) *poolAllocator {
	p := &poolAllocator{network: netip.MustParsePrefix(c.VPNNetwork),
		dual:     c.TCPManagementSocket != "",
		prefixes: make(map[string][]netip.Prefix), leases: make(map[uint64]poolLease), owners: make(map[netip.Addr]uint64)}
	for _, group := range c.GroupPools {
		for _, cidr := range group.ranges() {
			p.prefixes[group.GroupName] = append(p.prefixes[group.GroupName], netip.MustParsePrefix(cidr))
		}
	}
	return p
}

func (p *poolAllocator) acquire(cid uint64, groupName string) (netip.Addr, error) {
	if p.dual && cid >= 2*transportCIDBit {
		return netip.Addr{}, errors.New("invalid transport client ID")
	}
	if lease, exists := p.leases[cid]; exists {
		if lease.groupName != groupName {
			return netip.Addr{}, errors.New("connection already belongs to another group")
		}
		return lease.address, nil
	}
	prefixes, exists := p.prefixes[groupName]
	if !exists {
		return netip.Addr{}, errNoGroup
	}
	network := p.network
	gateway := network.Addr().Next()
	for _, prefix := range prefixes {
		for ip := prefix.Addr().Next(); prefix.Contains(ip) && prefix.Contains(ip.Next()); ip = ip.Next() {
			if !network.Contains(ip) || ip == network.Addr() || !network.Contains(ip.Next()) || ip == gateway {
				continue
			}
			if _, used := p.owners[ip]; used {
				continue
			}
			p.owners[ip], p.leases[cid] = cid, poolLease{address: ip, groupName: groupName}
			return ip, nil
		}
	}
	return netip.Addr{}, errPoolFull
}

func (p *poolAllocator) release(cid uint64) {
	if lease, exists := p.leases[cid]; exists {
		delete(p.owners, lease.address)
		delete(p.leases, cid)
	}
}

func (p *poolAllocator) netmask() string {
	return net.IP(net.CIDRMask(p.network.Bits(), 32)).String()
}

// OpenVPN supplies ifconfig_pool_remote_ip from the server's ifconfig-push.
// Reject learning any other IPv4, IPv6, or routed subnet, including another
// client's address. This hook neither reads config nor calls the management API.
func allowLearnedAddress(args []string, assigned string) bool {
	if len(args) < 2 || len(args) > 3 {
		return false
	}
	if args[0] == "delete" {
		return true
	}
	if args[0] != "add" && args[0] != "update" {
		return false
	}
	ip, err := netip.ParseAddr(args[1])
	expected, expectedErr := netip.ParseAddr(assigned)
	return err == nil && expectedErr == nil && ip.Is4() && expected.Is4() && ip == expected
}
