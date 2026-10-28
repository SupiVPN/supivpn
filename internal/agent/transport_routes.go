// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"time"
)

// Only OpenVPN's existing privileged hook process changes routes. The long-lived
// agent keeps its existing capabilities. Never use shell expansion, client
// environment PATH, or client-provided device/network names.
const clientRouteMetric = "42760"

var routeDeviceName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)
var errClientRoute = errors.New("shared-pool client route refused")

type hostRoute struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Protocol    string `json:"protocol"`
	Scope       string `json:"scope"`
	Metric      int    `json:"metric"`
	Gateway     string `json:"gateway"`
	Type        string `json:"type"`
}

func updateClientRoute(args []string, assigned, device, network string, run func(...string) ([]byte, error)) error {
	prefix, err := privatePrefix(network)
	if err != nil || !routeDeviceName.MatchString(device) || len(args) < 2 || len(args) > 3 {
		return errClientRoute
	}
	ip, err := netip.ParseAddr(args[1])
	if err != nil || !ip.Is4() || !prefix.Contains(ip) || ip == prefix.Addr() || ip == prefix.Addr().Next() || !prefix.Contains(ip.Next()) {
		return errClientRoute
	}
	// learn-address deletion is deferred by OpenVPN's route garbage collector.
	// It can arrive AFTER this IP has been reassigned. Cleanup belongs only to
	// client-disconnect, which upstream calls before its management DISCONNECT.
	if args[0] == "delete" {
		return nil
	}
	if args[0] != "disconnect" && !allowLearnedAddress(args, assigned) {
		return errClientRoute
	}
	if args[0] == "disconnect" && (len(args) != 2 || assigned != ip.String()) {
		return errClientRoute
	}
	raw, err := run("-j", "-4", "route", "show", "table", "main", "exact", ip.String()+"/32")
	if err != nil || len(raw) > 16384 {
		return errClientRoute
	}
	var routes []hostRoute
	if json.Unmarshal(raw, &routes) != nil {
		return errClientRoute
	}
	owned := len(routes) == 1 && (routes[0].Destination == ip.String() || routes[0].Destination == ip.String()+"/32") &&
		routes[0].Device == device && routes[0].Protocol == "static" && routes[0].Scope == "link" && routes[0].Metric == 42760 &&
		routes[0].Gateway == "" && (routes[0].Type == "" || routes[0].Type == "unicast")
	if args[0] == "disconnect" {
		if !owned {
			return nil
		} // An old daemon must never remove a successor's route.
		_, err = run("-4", "route", "del", ip.String()+"/32", "dev", device, "table", "main", "proto", "static", "scope", "link", "metric", clientRouteMetric)
	} else {
		if owned {
			return nil
		} // Idempotent learn/update for the same daemon.
		if len(routes) != 0 {
			return errClientRoute
		} // Never replace another route.
		_, err = run("-4", "route", "add", ip.String()+"/32", "dev", device, "table", "main", "proto", "static", "scope", "link", "metric", clientRouteMetric)
	}
	if err != nil {
		return errClientRoute
	}
	return nil
}

type boundedRouteOutput struct{ bytes.Buffer }

func (b *boundedRouteOutput) Write(p []byte) (int, error) {
	if len(p)+b.Len() > 16384 {
		return 0, errClientRoute
	}
	return b.Buffer.Write(p)
}

func runRouteCommand(args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errClientRoute
	}
	// The route mutator only accepts a TUN interface, not an Ethernet device or
	// loopback. All arguments originate in updateClientRoute's fixed grammar.
	for i, arg := range args {
		if arg == "dev" && i+1 < len(args) {
			iface, err := net.InterfaceByName(args[i+1])
			if err != nil || iface.Flags&net.FlagPointToPoint == 0 {
				return nil, errClientRoute
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/ip", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var out boundedRouteOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errClientRoute
	}
	return out.Bytes(), nil
}
