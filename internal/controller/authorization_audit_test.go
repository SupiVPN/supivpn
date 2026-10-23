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

// Validation and admission can use different clocks (controller and database),
// or a clock can move backwards between them. Carry the complete signed lower
// bound into the atomic decision instead of only checking it while parsing.
func TestAuthorizationPreservesBearerNotBefore(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	acs, err := url.Parse("https://vpn.example.test/saml/acs")
	if err != nil {
		t.Fatal(err)
	}
	a := &Controller{config: Config{SessionSeconds: 3600},
		allowed: map[string]bool{"test-user": true},
		sp:      &saml.ServiceProvider{EntityID: "vpn", AcsURL: *acs},
		now:     func() time.Time { return now }}
	for _, tc := range []struct {
		name                    string
		condition, confirmation time.Time
		want                    time.Time
	}{
		{"bearer-later", now.Add(-time.Minute), now.Add(-time.Second), now.Add(-time.Second)},
		{"conditions-later", now.Add(-time.Second), now.Add(-time.Minute), now.Add(-time.Second)},
		{"bearer-omitted", now.Add(-time.Minute), time.Time{}, now.Add(-time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertion := policyAssertion(now, *acs)
			assertion.Conditions.NotBefore = tc.condition
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = tc.confirmation
			if !a.acceptableAssertion(assertion, "request-7") {
				t.Fatal("valid assertion refused at the controller clock")
			}
			decision := a.authorizationBounds(assertion, "request-7", "")
			if !decision.NotBefore.Equal(tc.want) || !decision.ValidAt(now) ||
				decision.ValidAt(tc.want.Add(-time.Nanosecond)) || !decision.ValidAt(tc.want) {
				t.Fatal("admission widened the signed lower validity bound")
			}
		})
	}
}
