// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"supivpn/internal/saml"
)

func assertionOnlyResponse(t *testing.T, a *testApplication, signer *saml.ServiceProvider, assertion *saml.Assertion, requestID string) string {
	t.Helper()
	form, err := url.ParseQuery(responseBody(t, a, signer, assertion, false, false))
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	ctx, err := saml.GetSigningContext(signer)
	if err != nil {
		t.Fatal(err)
	}
	old := root.FindElement("./Assertion")
	signed, err := ctx.SignEnveloped(old)
	if err != nil {
		t.Fatal(err)
	}
	root.RemoveChild(old)
	root.AddChild(signed)
	// Only the outer envelope is changed AFTER the assertion was signed.
	root.CreateAttr("InResponseTo", requestID)
	data, err = doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Prove the cryptographic verifier accepts this assertion. The controller
	// must still enforce the signed bearer confirmation for this pending login.
	if _, err := a.sp.ParseXMLResponse(data, []string{requestID}, a.sp.AcsURL); err != nil {
		t.Fatal("fixture must pass signature verification before correlation checks")
	}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(data))
	return form.Encode()
}

func TestSecurityAssertionOnlyRequestSubstitution(t *testing.T) {
	signer, md := testIdP(t)
	original, originalCommands := testApp(t, md)
	target, targetCommands := testApp(t, md)
	target.tickets["test-ticket"].requestID = "request-8"

	stolen := assertionFor(original)
	attack := assertionOnlyResponse(t, target, signer, stolen, "request-8")
	if submit(target, attack, "test-browser").Code != http.StatusForbidden ||
		len(targetCommands) != 0 || target.connections[7].active {
		t.Fatal("unsigned envelope rebound a signed assertion to another login")
	}

	// The rejected attack must not consume either legitimate pending request.
	if submit(original, assertionOnlyResponse(t, original, signer, stolen, "request-7"), "test-browser").Code != http.StatusOK ||
		len(originalCommands) != 1 {
		t.Fatal("failed substitution consumed the original login")
	}
	fresh := assertionFor(target)
	fresh.ID = "assertion-8"
	fresh.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "request-8"
	if submit(target, assertionOnlyResponse(t, target, signer, fresh, "request-8"), "test-browser").Code != http.StatusOK ||
		len(targetCommands) != 1 {
		t.Fatal("failed substitution poisoned the target login")
	}
	if submit(target, attack, "test-browser").Code == http.StatusOK || len(targetCommands) != 1 {
		t.Fatal("substitution or replay authorized an extra connection")
	}
}
