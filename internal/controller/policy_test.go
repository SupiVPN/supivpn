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

func policyAssertion(now time.Time, acs url.URL) *saml.Assertion {
	return &saml.Assertion{
		ID: "assertion-7",
		Conditions: &saml.Conditions{
			NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: "vpn"}}},
		},
		AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now}},
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "test-user"}, SubjectConfirmations: []saml.SubjectConfirmation{{
			Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
			SubjectConfirmationData: &saml.SubjectConfirmationData{
				InResponseTo: "request-7", Recipient: acs.String(), NotBefore: now, NotOnOrAfter: now.Add(30 * time.Second),
			},
		}}},
	}
}

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
			assertion := policyAssertion(now, *acs)
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

func TestBearerConfirmationBindingAndClockRecheck(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	acs, _ := url.Parse("https://vpn.example.test/saml/acs")
	a := &Controller{config: Config{SessionSeconds: 43200}, allowed: map[string]bool{"test-user": true},
		sp: &saml.ServiceProvider{EntityID: "vpn", AcsURL: *acs}, now: func() time.Time { return now }}
	for _, tc := range []struct {
		name string
		edit func(*saml.SubjectConfirmation)
	}{
		{"method", func(c *saml.SubjectConfirmation) { c.Method = "other" }},
		{"missing-data", func(c *saml.SubjectConfirmation) { c.SubjectConfirmationData = nil }},
		{"request", func(c *saml.SubjectConfirmation) { c.SubjectConfirmationData.InResponseTo = "other" }},
		{"recipient", func(c *saml.SubjectConfirmation) {
			c.SubjectConfirmationData.Recipient = "https://other.example.test/acs"
		}},
		{"future", func(c *saml.SubjectConfirmation) { c.SubjectConfirmationData.NotBefore = now.Add(time.Nanosecond) }},
		{"expired", func(c *saml.SubjectConfirmation) { c.SubjectConfirmationData.NotOnOrAfter = now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertion := policyAssertion(now, *acs)
			if !a.acceptableAssertion(assertion, "request-7") {
				t.Fatal("valid policy fixture refused")
			}
			tc.edit(&assertion.Subject.SubjectConfirmations[0])
			if a.acceptableAssertion(assertion, "request-7") || a.authorizationBounds(assertion, "request-7", "").ValidAt(now) {
				t.Fatal("invalid bearer confirmation accepted")
			}
			// Ignore the unusable confirmation and choose the first valid one.
			assertion.Subject.SubjectConfirmations = append(assertion.Subject.SubjectConfirmations,
				policyAssertion(now, *acs).Subject.SubjectConfirmations...)
			if !a.acceptableAssertion(assertion, "request-7") || !a.authorizationBounds(assertion, "request-7", "").ValidAt(now) {
				t.Fatal("valid alternate confirmation refused")
			}
		})
	}
	assertion := policyAssertion(now, *acs)
	if !a.acceptableAssertion(assertion, "request-7") {
		t.Fatal("valid assertion refused")
	}
	now = now.Add(30 * time.Second)
	if d := a.authorizationBounds(assertion, "request-7", ""); !d.NotOnOrAfter.IsZero() || d.ValidAt(now) {
		t.Fatal("confirmation expiry between validation and extraction did not fail closed")
	}
}
