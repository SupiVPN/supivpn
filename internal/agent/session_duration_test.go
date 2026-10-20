// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only


package agent

import (
    "net/http"
    "testing"
    "time"

    "supivpn/internal/controller"
    "supivpn/internal/controlruntime"
    "supivpn/internal/saml"
)

func TestSessionDurationConfiguration(t *testing.T) {
    for _, seconds := range []int{-1, 1, 59, 43201} {
        c := groupConfig()
        c.GroupPools[0].SessionSeconds = intPointer(seconds)
        if validateAuthorization(c) == nil {
            t.Fatalf("invalid group session duration accepted: %d", seconds)
        }
    }
    c := groupConfig()
    c.SessionSeconds = 3600
    c.GroupPools[0].SessionSeconds = intPointer(600)
    c.GroupPools[1].SessionSeconds = intPointer(43200)
    if err := validateAuthorization(c); err != nil { t.Fatal(err) }
    p := controller.Config{Policy: controllerPolicy(c), SessionSeconds: c.SessionSeconds}
    for group, want := range map[string]int{coreGroup: 43200, devGroup: 600, "": 3600} {
        if p.SessionLimit(group) != want { t.Fatal("agent lost session policy") }
    }
    raw := `{"public_url":"https://vpn.example.test","idp_metadata":"/etc/supivpn/idp-metadata.xml","saml_groups_attribute":"groups","pending_seconds":180,"session_seconds":3600,"groups":[{"name":"admins-vpn","priority":10,"session_seconds":43200},{"name":"engineers-production-vpn","priority":20}]}`
    cfg, err := controlruntime.ParseConfig(raw)
    if err != nil { t.Fatal(err) }
    runtimePolicy, _, err := cfg.Policy()
    if err != nil || runtimePolicy.SessionLimit(coreGroup) != 43200 || runtimePolicy.SessionLimit(devGroup) != 3600 {
        t.Fatal("VM/Lambda JSON lost override or inheritance")
    }
    cfg.Groups[0].SessionSeconds = intPointer(59)
    if _, _, err := cfg.Policy(); err == nil { t.Fatal("controller accepted invalid group duration") }
}

func TestSignedSAMLSessionDuration(t *testing.T) {
    signer, md := testIdP(t)
    for _, tc := range []struct {
        name string
        groups []string
        idp []time.Duration
        want time.Duration
        denied bool
    }{
        {"inherit", []string{devGroup}, nil, time.Hour, false},
        {"selected-priority-override", []string{devGroup, coreGroup}, nil, 12*time.Hour, false},
        {"idp-shorter", []string{coreGroup}, []time.Duration{20*time.Minute}, 20*time.Minute, false},
        {"policy-shorter", []string{devGroup}, []time.Duration{24*time.Hour}, time.Hour, false},
        {"earliest-idp-statement", []string{coreGroup}, []time.Duration{time.Hour, 10*time.Minute}, 10*time.Minute, false},
        {"expired-idp", []string{coreGroup}, []time.Duration{-time.Second}, 0, true},
        {"exact-idp-deadline", []string{coreGroup}, []time.Duration{0}, 0, true},
    } {
        t.Run(tc.name, func(t *testing.T) {
            a, commands := testApp(t, md)
            enableTestGroups(a)
            now := time.Now().UTC().Truncate(time.Second)
            a.now = func() time.Time { return now }
            a.config.SessionSeconds = 3600
            a.config.GroupPools[1].SessionSeconds = intPointer(43200)
            assertion := groupAssertionFor(a, tc.groups...)
            if tc.idp != nil {
                assertion.AuthnStatements = nil
                for _, lifetime := range tc.idp {
                    deadline := now.Add(lifetime)
                    assertion.AuthnStatements = append(assertion.AuthnStatements, saml.AuthnStatement{
                        AuthnInstant: now.Add(-time.Hour), SessionNotOnOrAfter: &deadline,
                    })
                }
            }
            w := submit(a, responseBody(t, a, signer, assertion, true, false), "test-browser")
            if tc.denied {
                if w.Code != http.StatusForbidden || len(commands) != 0 || a.connections[7].active {
                    t.Fatal("expired signed IdP session authorized")
                }
                return
            }
            if w.Code != http.StatusOK || !a.connections[7].expires.Equal(now.Add(tc.want)) {
                t.Fatalf("wrong signed session bound: status=%d expiry=%v", w.Code, a.connections[7].expires)
            }
            <-commands
            // The short assertion delivery window must not replace the VPN deadline.
            a.now = func() time.Time { return now.Add(tc.want) }
            a.expire()
            if cmd := <-commands; cmd != "client-kill 7" { t.Fatal("session deadline not enforced") }
        })
    }
}

func TestRemoteDecisionUsesSelectedGroupDuration(t *testing.T) {
    for _, tc := range []struct { name, group string; lifetime time.Duration; valid bool }{
        {"override-longer-than-default", coreGroup, 2*time.Hour, true},
        {"override-shorter-than-default", devGroup, 5*time.Minute, true},
        {"over-short-group-limit", devGroup, 15*time.Minute, false},
        {"over-long-group-limit", coreGroup, 13*time.Hour, false},
    } {
        t.Run(tc.name, func(t *testing.T) {
            a, _ := remoteFixture(t, nil)
            a.config.SessionSeconds = 3600
            a.config.GroupPools[0].SessionSeconds = intPointer(600)
            a.config.GroupPools[1].SessionSeconds = intPointer(43200)
            d := allowedRemoteDecision(tc.group)
            d.SessionExpiresAt = a.now().Add(tc.lifetime)
            if a.validRemoteDecision(&connection{cid: 7, kid: 2}, d) != tc.valid {
                t.Fatal("remote duration cap ignored selected group")
            }
        })
    }
}

func intPointer(n int) *int { return &n }
