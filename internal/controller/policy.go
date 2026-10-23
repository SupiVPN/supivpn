// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/sha256"
	"time"

	"supivpn/internal/saml"
)

// These are additional constraints on an already signature-validated assertion.
// Never use this function alone to authenticate XML.
func (a *Controller) acceptableAssertion(assertion *saml.Assertion, requestID string) bool {
	if assertion == nil || assertion.ID == "" || assertion.Subject == nil || assertion.Subject.NameID == nil ||
		assertion.Conditions == nil || len(assertion.AuthnStatements) == 0 ||
		assertion.Subject.NameID.Value == "" ||
		(a.config.SAMLGroupsAttribute == "" && !a.allowed[assertion.Subject.NameID.Value]) {
		return false
	}
	now := a.now()
	for _, statement := range assertion.AuthnStatements {
		if statement.SessionNotOnOrAfter != nil && !now.Before(*statement.SessionNotOnOrAfter) {
			return false
		}
	}
	conditions := assertion.Conditions
	if conditions.NotOnOrAfter.IsZero() || !now.Before(conditions.NotOnOrAfter) ||
		now.Before(conditions.NotBefore) || len(conditions.AudienceRestrictions) == 0 {
		return false
	}
	for _, restriction := range conditions.AudienceRestrictions {
		if restriction.Audience.Value != a.sp.EntityID {
			return false
		}
	}
	return a.bearerConfirmation(assertion, requestID, now) != nil
}

func (a *Controller) bearerConfirmation(assertion *saml.Assertion, requestID string, now time.Time) *saml.SubjectConfirmationData {
	for _, confirmation := range assertion.Subject.SubjectConfirmations {
		data := confirmation.SubjectConfirmationData
		if confirmation.Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" &&
			data != nil && data.InResponseTo == requestID &&
			data.Recipient == a.sp.AcsURL.String() && !now.Before(data.NotBefore) && now.Before(data.NotOnOrAfter) {
			return data
		}
	}
	return nil
}

// authorizationBounds preserves the strict time checks at the final commit,
// which can happen later than signature validation. It selects a bearer
// confirmation that was valid during verification and carries its deadline.
func (a *Controller) authorizationBounds(assertion *saml.Assertion, requestID, groupName string) Authorization {
	now := a.now()
	decision := Authorization{
		SubjectHash:        sha256.Sum256([]byte(assertion.Issuer.Value + "\x00" + assertion.Subject.NameID.Value)),
		AssertionHash:      sha256.Sum256([]byte(assertion.Issuer.Value + "\x00" + assertion.ID)),
		AssertionExpiresAt: assertion.Conditions.NotOnOrAfter,
		NotBefore:          assertion.Conditions.NotBefore,
		NotOnOrAfter:       assertion.Conditions.NotOnOrAfter,
		SessionUnlimited:   a.config.SessionLimit(groupName) == 0,
		GroupName:          groupName,
	}
	// Audit metadata must not change authorization for an otherwise valid NameID.
	if username := assertion.Subject.NameID.Value; ValidLogUsername(username) {
		decision.Username = username
	}
	if !decision.SessionUnlimited {
		decision.SessionExpiresAt = now.Add(time.Duration(a.config.SessionLimit(groupName)) * time.Second)
	}
	for _, statement := range assertion.AuthnStatements {
		if statement.SessionNotOnOrAfter != nil {
			if decision.SessionUnlimited || statement.SessionNotOnOrAfter.Before(decision.SessionExpiresAt) {
				decision.SessionUnlimited = false
				decision.SessionExpiresAt = *statement.SessionNotOnOrAfter
			}
			if statement.SessionNotOnOrAfter.Before(decision.NotOnOrAfter) {
				decision.NotOnOrAfter = *statement.SessionNotOnOrAfter
			}
		}
	}
	if data := a.bearerConfirmation(assertion, requestID, now); data != nil {
		if data.NotBefore.After(decision.NotBefore) {
			decision.NotBefore = data.NotBefore
		}
		if data.NotOnOrAfter.Before(decision.NotOnOrAfter) {
			decision.NotOnOrAfter = data.NotOnOrAfter
		}
		if !decision.SessionUnlimited && decision.SessionExpiresAt.Before(decision.NotOnOrAfter) {
			decision.NotOnOrAfter = decision.SessionExpiresAt
		}
		return decision
	}
	// A clock change between validation and extraction must fail closed.
	decision.NotOnOrAfter = time.Time{}
	return decision
}
