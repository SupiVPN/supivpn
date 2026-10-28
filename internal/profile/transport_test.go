// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBoundTransportProfiles(t *testing.T) {
	template, err := os.ReadFile("../../examples/client.ovpn.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, tcp := range []uint16{0, 443, 1443} {
		var saved Credential
		owner := Owner{SubjectHash: [32]byte{1}, Username: "private-owner"}
		fail := false
		issue, err := BoundTransportIssuer(template, "vpn.example.test", 1195, tcp,
			func(context.Context) ([]byte, error) { return testKey(serverType), nil },
			func(_ context.Context, c Credential, got Owner) error {
				if got != owner {
					t.Fatal("owner changed with transport")
				}
				saved = c
				if fail {
					return errors.New("synthetic persistence failure")
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		data, err := issue(context.Background(), owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, shared := range []string{"<ca>", "<tls-crypt-v2>", "<auth-user-pass>", "verify-x509-name vpn.example.test name", saved.ID, saved.Secret} {
			if bytes.Count(data, []byte(shared)) != 1 {
				t.Fatal("shared trust or proof duplicated or absent")
			}
		}
		if bytes.Contains(data, []byte(owner.Username)) {
			t.Fatal("identity leaked into profile")
		}
		s := string(data)
		if tcp == 0 {
			if strings.Contains(s, "<connection>") || !strings.Contains(s, "proto udp4\nremote vpn.example.test 1195\n") {
				t.Fatal("UDP-only profile changed")
			}
		} else {
			if strings.Count(s, "<connection>") != 2 || strings.Index(s, "proto udp4") > strings.Index(s, "proto tcp4-client") ||
				strings.Count(s, "connect-timeout 3") != 2 || strings.Count(s, "server-poll-timeout 3") != 1 || strings.Count(s, "hand-window 180") != 1 || strings.LastIndex(s, "</connection>") > strings.Index(s, "<auth-user-pass>") {
				t.Fatal("transport order or shared credential scope changed")
			}
		}
		fail = true
		if data, err := issue(context.Background(), owner); err == nil || len(data) != 0 {
			t.Fatal("failed persistence disclosed a profile")
		}
	}
	for _, addition := range []string{"remote attacker.example.test 443\n", "remote-random\n", "<connection>\nproto tcp-client\n</connection>\n", "http-proxy proxy.example.test 80\n", "proto tcp4-client\n", "server-poll-timeout 60\n", "connect-timeout 60\n"} {
		_, err := BoundTransportIssuer(append(append([]byte{}, template...), []byte(addition)...), "vpn.example.test", 1195, 443,
			func(context.Context) ([]byte, error) { t.Fatal("loaded key during validation"); return nil, nil },
			func(context.Context, Credential, Owner) error { return nil })
		if err == nil {
			t.Fatal("ambiguous fallback template accepted")
		}
	}
}
