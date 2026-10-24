// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/url"
	"strings"
	"supivpn/internal/profile"
	"testing"
	"time"
)

func TestDeviceAuditUntrustedLabels(t *testing.T) {
	for _, tc := range []struct{ env, id, source string }{
		{"UV_UUID=connect-123", "connect-123", "UV_UUID"},
		{"IV_HWADDR=aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "IV_HWADDR"},
		{"UV_UUID=connect-123\nIV_HWADDR=linux-456", "connect-123", "UV_UUID"},
		{"IV_HWADDR=linux-456\nUV_UUID=connect-123", "connect-123", "UV_UUID"},
		{"UV_UUID=first\nUV_UUID=second\nUV_UUID=third", "", ""},
		{"IV_HWADDR=first\nIV_HWADDR=second", "", ""},
		{"UV_UUID=\nIV_HWADDR=fallback", "", ""},
		{"UV_UUID=forged\rentry", "", ""},
		{"UV_UUID=forged\u202eentry", "", ""},
		{"UV_UUID=" + strings.Repeat("a", 129), "", ""},
		{"UV_UUID= leading-space", "", ""},
		{"UV_DEVICE_ID=unselected", "", ""},
		{"", "", ""},
	} {
		e := envEvent(t, "CONNECT,7,2", tc.env)
		if e.client.deviceID != tc.id || e.client.deviceIDSource != tc.source {
			t.Fatal("invalid device diagnostic selection")
		}
		for _, header := range []string{"REAUTH,7,3", "ESTABLISHED,7", "DISCONNECT,7"} {
			if e := envEvent(t, header, tc.env); e.client.deviceID != "" {
				t.Fatal("later event replaced device diagnostic")
			}
		}
	}
}

func TestDeviceAuditDoesNotAuthorizeOrCrossSessions(t *testing.T) {
	origin, _ := url.Parse("https://vpn.example.test")
	a := newAgent(groupConfig(), origin)
	a.attach(statusManagement(t, func(string) string { return "SUCCESS: acknowledged\n" }))
	logs := captureAudit(t, a)
	a.handleEvent(envEvent(t, "CONNECT,7,2", "IV_SSO=webauth\nUV_UUID=device-one"))
	c := a.connections[7]
	if c == nil || c.active {
		t.Fatal("device ID authorized a session")
	}
	// Model authorization completion independently from the claimed device ID.
	c.active, c.username, c.expires = true, "verified-user", time.Now().Add(time.Hour)
	proof, _ := profile.NewCredential()
	c.proof.ID = proof.ID
	a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
	row := auditRow(t, logs, "vpn.tunnel_established", 7)
	if row["client_device_id"] != "device-one" || row["client_device_id_source"] != "UV_UUID" {
		t.Fatal("missing device audit")
	}
	if row["profile_id"] != proof.ID {
		t.Fatal("profile/device correlation missing")
	}
	a.handleEvent(envEvent(t, "REAUTH,7,3", "UV_UUID=device-two"))
	if c.client.deviceID != "device-one" {
		t.Fatal("reauth replaced original device label")
	}
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	a.handleEvent(envEvent(t, "CONNECT,7,4", "IV_SSO=webauth"))
	if a.connections[7] == nil || a.connections[7].client.deviceID != "" || a.connections[7].active {
		t.Fatal("device ID crossed sessions or became required")
	}
}
