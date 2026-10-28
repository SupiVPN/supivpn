// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"supivpn/internal/controller"
	"supivpn/internal/controlruntime"
	"supivpn/internal/saml"
	"testing"
	"time"
)

func TestUnlimitedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        int
	}{
		{"omitted", "", 43200}, {"zero", `,"session_seconds":0`, 0}, {"finite", `,"session_seconds":600`, 600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"public_url":"https://vpn.example.test","idp_metadata":"/etc/supivpn/idp-metadata.xml","saml_groups_attribute":"groups","pending_seconds":180,"groups":[{"name":"admins-vpn","priority":10},{"name":"engineers-production-vpn","priority":20,"session_seconds":0}]` + tc.field + "}"
			c, err := controlruntime.ParseConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			policy, _, err := c.Policy()
			if err != nil || policy.SessionLimit(coreGroup) != tc.want || policy.SessionLimit(devGroup) != 0 {
				t.Fatal("controller lost explicit zero or inheritance")
			}
			// Agent file decoding has the same default as VM/Lambda.
			cfg := groupConfig()
			cfg.RemoteController = localControllerConfig()
			data, _ := json.Marshal(cfg)
			var fields map[string]any
			if json.Unmarshal(data, &fields) != nil {
				t.Fatal("fixture")
			}
			delete(fields, "session_seconds")
			if tc.name != "omitted" {
				fields["session_seconds"] = tc.want
			}
			fields["public_url"] = "https://vpn.example.test"
			fields["listen"] = "127.0.0.1:8443"
			for _, key := range []string{"tls_certificate", "tls_chain", "tls_private_key", "idp_metadata", "management_socket"} {
				fields[key] = "/etc/supivpn/test"
			}
			fields["pending_seconds"] = 180
			data, _ = json.Marshal(fields)
			path := filepath.Join(t.TempDir(), "config.json")
			if os.WriteFile(path, data, 0600) != nil {
				t.Fatal("fixture write")
			}
			actual, _, err := readConfig(path)
			if err != nil || actual.SessionSeconds != tc.want {
				t.Fatalf("agent default/zero: %v", err)
			}
		})
	}
	cfg, _ := controlruntime.ParseConfig(`{"session_seconds":600,"groups":[{"name":"admins-vpn","session_seconds":null}]}`)
	if cfg.Groups[0].SessionSeconds != nil {
		t.Fatal("null must inherit")
	}
}

func TestUnlimitedSignedSAMLAndIdPCap(t *testing.T) {
	signer, md := testIdP(t)
	for _, tc := range []struct {
		name   string
		idp    time.Duration
		denied bool
	}{
		{"no-idp-limit", 0, false}, {"short-idp", time.Minute, false},
		{"idp-longer-than-default", 24 * time.Hour, false}, {"expired-idp", -time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, commands := testApp(t, md)
			enableTestGroups(a)
			now := time.Now().UTC().Truncate(time.Second)
			a.now = func() time.Time { return now }
			a.config.GroupPools[1].SessionSeconds = intPointer(0)
			assertion := groupAssertionFor(a, coreGroup)
			assertion.AuthnStatements = []saml.AuthnStatement{{AuthnInstant: now.Add(-time.Minute)}}
			if tc.idp != 0 {
				expiry := now.Add(tc.idp)
				assertion.AuthnStatements = []saml.AuthnStatement{{AuthnInstant: now.Add(-time.Minute), SessionNotOnOrAfter: &expiry}}
			}
			w := submit(a, responseBody(t, a, signer, assertion, true, false), "test-browser")
			if tc.denied {
				if w.Code != http.StatusForbidden || len(commands) != 0 {
					t.Fatal("expired IdP granted unlimited access")
				}
				return
			}
			c := a.connections[7]
			if w.Code != http.StatusOK || !c.active || c.sessionUnlimited != (tc.idp == 0) {
				t.Fatal("wrong authorization mode")
			}
			<-commands
			if tc.idp != 0 {
				if !c.expires.Equal(now.Add(tc.idp)) {
					t.Fatal("signed IdP deadline lost")
				}
				now = c.expires
				a.expire()
				if cmd := <-commands; cmd != "client-kill 7" {
					t.Fatal("IdP expiry ignored")
				}
				return
			}
			if !c.expires.IsZero() {
				t.Fatal("unlimited must have no synthetic expiry")
			}
			now = now.Add(365 * 24 * time.Hour)
			a.expire()
			if len(commands) != 0 || c.closing {
				t.Fatal("unlimited session expired or opened browser")
			}
			a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3})
			if cmd := <-commands; cmd != "client-auth-nt 7 3" {
				t.Fatal("TLS rekey did not preserve unlimited session")
			}
		})
	}
}

func TestUnlimitedRemoteDecisionValidation(t *testing.T) {
	a, _ := remoteFixture(t, nil)
	d := allowedRemoteDecision(coreGroup)
	d.SessionExpiresAt = time.Time{}
	if a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("missing expiry implicitly unlimited")
	}
	d.SessionUnlimited = true
	if a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("remote bypassed finite local policy")
	}
	a.config.GroupPools[1].SessionSeconds = intPointer(0)
	if !a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("explicit unlimited refused")
	}
	d.SessionExpiresAt = a.now().Add(24 * time.Hour)
	if a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("contradictory unlimited decision accepted")
	}
	d.SessionUnlimited = false
	if !a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("IdP limit capped by disabled local limit")
	}
	d.ExpiresAt = a.now().Add(-time.Second)
	if a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) {
		t.Fatal("unlimited bypassed delivery expiry")
	}
	policy := controller.Config{Policy: controllerPolicy(a.config), SessionSeconds: 43200}
	if !policy.HasUnlimitedSessions() {
		t.Fatal("unlimited security warning missing")
	}
}

func TestUnlimitedSessionStillRequiresNodeHeartbeat(t *testing.T) {
	a, _ := remoteFixture(t, nil)
	c := &connection{cid: 7, kid: 2, active: true, sessionUnlimited: true}
	a.connections[7] = c
	deadline := a.remote.leaseUntil
	a.now = func() time.Time { return deadline }
	a.expire()
	select {
	case <-a.management.done:
	default:
		t.Fatal("unlimited bypassed heartbeat expiry")
	}
}
