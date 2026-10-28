// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestTransportRouteValidation(t *testing.T) {
	for _, tc := range []struct{ op, ip, assigned, device, network string }{
		{"add", "10.203.0.2", "10.203.0.3", "supivpn0", "10.203.0.0/24"},
		{"add", "10.204.0.2", "10.204.0.2", "supivpn0", "10.203.0.0/24"},
		{"add", "10.203.0.1", "10.203.0.1", "supivpn0", "10.203.0.0/24"},
		{"add", "10.203.0.255", "10.203.0.255", "supivpn0", "10.203.0.0/24"},
		{"add", "10.203.0.2/32", "10.203.0.2", "supivpn0", "10.203.0.0/24"},
		{"add", "10.203.0.2", "10.203.0.2", "tun0;id", "10.203.0.0/24"},
		{"add", "10.203.0.2", "10.203.0.2", "../tun0", "10.203.0.0/24"},
		{"replace", "10.203.0.2", "10.203.0.2", "supivpn0", "10.203.0.0/24"},
		{"disconnect", "10.203.0.2", "10.203.0.3", "supivpn0", "10.203.0.0/24"},
	} {
		called := false
		err := updateClientRoute([]string{tc.op, tc.ip}, tc.assigned, tc.device, tc.network, func(...string) ([]byte, error) { called = true; return nil, nil })
		if err == nil || called {
			t.Fatal("invalid input reached route command")
		}
	}
}

func TestTransportRouteOwnershipAndDelayedDelete(t *testing.T) {
	own := hostRoute{Destination: "10.203.0.2", Device: "supivpn0", Protocol: "static", Scope: "link", Metric: 42760}
	for _, tc := range []struct {
		name, op string
		routes   []hostRoute
		want     string
		fail     bool
	}{
		{"add", "add", []hostRoute{}, "add", false},
		{"idempotent", "update", []hostRoute{own}, "", false},
		{"disconnect", "disconnect", []hostRoute{own}, "del", false},
		{"delayed garbage collection", "delete", []hostRoute{own}, "", false},
		{"foreign route", "add", []hostRoute{{Destination: "10.203.0.2", Device: "supivpn1"}}, "", true},
		{"successor route", "disconnect", []hostRoute{{Destination: "10.203.0.2", Device: "supivpn1", Protocol: "static", Scope: "link", Metric: 42760}}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mutation []string
			err := updateClientRoute([]string{tc.op, "10.203.0.2"}, "10.203.0.2", "supivpn0", "10.203.0.0/24", func(args ...string) ([]byte, error) {
				if args[0] == "-j" {
					return json.Marshal(tc.routes)
				}
				mutation = args
				return nil, nil
			})
			if (err != nil) != tc.fail {
				t.Fatal("incorrect route result", err)
			}
			if tc.want == "" {
				if mutation != nil {
					t.Fatal("unexpected route mutation")
				}
				return
			}
			if !reflect.DeepEqual(mutation, []string{"-4", "route", tc.want, "10.203.0.2/32", "dev", "supivpn0", "table", "main", "proto", "static", "scope", "link", "metric", "42760"}) {
				t.Fatal("unexpected route command", mutation)
			}
		})
	}
	if err := updateClientRoute([]string{"add", "10.203.0.2"}, "10.203.0.2", "supivpn0", "10.203.0.0/24", func(...string) ([]byte, error) { return nil, errors.New("synthetic failure") }); err == nil {
		t.Fatal("route lookup failure allowed traffic")
	}
}

// Runs only in the existing disposable NET_ADMIN/TUN container. Exercise real
// Linux FIB selection, including the late-callback race across two transports.
func TestOpenVPNSharedPoolRoutes(t *testing.T) {
	if os.Getenv("SUPIVPN_TEST_OPENVPN") == "" {
		t.Skip("requires isolated OpenVPN test container")
	}
	ipCommand := func(args ...string) []byte {
		t.Helper()
		b, err := exec.Command("/usr/sbin/ip", args...).Output()
		if err != nil {
			t.Fatal("isolated route test command failed", err)
		}
		return b
	}
	for _, dev := range []string{"supiRouteU", "supiRouteT"} {
		ipCommand("tuntap", "add", "dev", dev, "mode", "tun")
		t.Cleanup(func() { _ = exec.Command("/usr/sbin/ip", "link", "del", dev).Run() })
		ipCommand("addr", "add", "10.219.0.1/24", "dev", dev)
		ipCommand("link", "set", "dev", dev, "up")
	}
	apply := func(op, ip, dev string) {
		t.Helper()
		if err := updateClientRoute([]string{op, ip}, ip, dev, "10.219.0.0/24", runRouteCommand); err != nil {
			t.Fatal(op, "failed", err)
		}
	}
	check := func(ip, dev string) {
		t.Helper()
		var routes []hostRoute
		if json.Unmarshal(ipCommand("-j", "-4", "route", "get", ip), &routes) != nil || len(routes) != 1 || routes[0].Device != dev {
			t.Fatal("reply would use the wrong transport")
		}
	}
	apply("add", "10.219.0.2", "supiRouteU")
	apply("add", "10.219.0.3", "supiRouteT")
	check("10.219.0.2", "supiRouteU")
	check("10.219.0.3", "supiRouteT")
	if err := updateClientRoute([]string{"add", "10.219.0.2"}, "10.219.0.2", "supiRouteT", "10.219.0.0/24", runRouteCommand); err == nil {
		t.Fatal("route collision was overwritten")
	}
	apply("disconnect", "10.219.0.2", "supiRouteU")
	apply("add", "10.219.0.2", "supiRouteT")
	apply("delete", "10.219.0.2", "supiRouteU")
	apply("disconnect", "10.219.0.2", "supiRouteU")
	check("10.219.0.2", "supiRouteT")
	check("10.219.0.3", "supiRouteT")
}
