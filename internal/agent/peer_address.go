// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/netip"
	"strconv"
	"strings"
)

// Only daemon-generated endpoint fields are retained. IV_/UV_ peer information,
// credentials and arbitrary environment values never become audit metadata.
type peerEnvironment struct {
	ip                        netip.Addr
	port                      uint16
	seenIP, seenPort, invalid bool
}

func (p *peerEnvironment) add(kind, env string) {
	prefix := "trusted"
	switch kind {
	case "CONNECT", "REAUTH":
		prefix = "untrusted"
	case "ESTABLISHED", "DISCONNECT":
	default:
		return
	}
	name, value, ok := strings.Cut(env, "=")
	if !ok {
		return
	}
	switch name {
	case prefix + "_ip", prefix + "_ip6":
		ip, err := netip.ParseAddr(value)
		if p.seenIP || err != nil || ip.Zone() != "" ||
			(name == prefix+"_ip" && !ip.Is4()) || (name == prefix+"_ip6" && !ip.Is6()) {
			p.invalid = true
		}
		p.seenIP = true
		p.ip = ip.Unmap()
	case prefix + "_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if p.seenPort || err != nil || port == 0 {
			p.invalid = true
		}
		p.seenPort = true
		p.port = uint16(port)
	}
}

func (p peerEnvironment) endpoint() netip.AddrPort {
	if p.invalid || !p.seenIP || !p.seenPort {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(p.ip, p.port)
}
