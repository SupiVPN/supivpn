// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"net/url"
	"testing"
	"time"

	"supivpn/internal/saml"
)

func TestAssertionAndVPNSessionHaveSeparateDeadlines(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	acs, _ := url.Parse("https://vpn.example.test/saml/acs")
	for _, tc := range []struct {
		name        string
		idpLifetime time.Duration
		wantSession time.Duration
		wantCommit  time.Duration
	}{
		{"no-idp-deadline", 0, 12 * time.Hour, 30 * time.Second},
		{"short-idp-session", 20 * time.Second, 20 * time.Second, 20 * time.Second},
		{"long-idp-session", 24 * time.Hour, 12 * time.Hour, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Controller{config: Config{SessionSeconds: 43200},
				sp: &saml.ServiceProvider{AcsURL: *acs}, now: func() time.Time { return now }}
			assertion := &saml.Assertion{
				Conditions:      &saml.Conditions{NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute)},
				AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now}},
				Subject: &saml.Subject{NameID: &saml.NameID{Value: "test-user"}, SubjectConfirmations: []saml.SubjectConfirmation{{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: "request-7", Recipient: acs.String(), NotOnOrAfter: now.Add(30 * time.Second),
					},
				}}},
			}
			if tc.idpLifetime != 0 {
				expiry := now.Add(tc.idpLifetime)
				assertion.AuthnStatements[0].SessionNotOnOrAfter = &expiry
			}
			decision := a.authorizationBounds(assertion, "request-7", "")
			if !decision.ValidAt(now) ||
				!decision.SessionExpiresAt.Equal(now.Add(tc.wantSession)) ||
				!decision.NotOnOrAfter.Equal(now.Add(tc.wantCommit)) ||
				decision.ValidAt(now.Add(tc.wantCommit)) {
				t.Fatal("assertion admission deadline or VPN session deadline changed")
			}
		})
	}
}
