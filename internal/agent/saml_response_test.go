// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"supivpn/internal/saml"
)

func responseDocument(t *testing.T, body string) *etree.Document {
	t.Helper()
	form, err := url.ParseQuery(body)
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
	return doc
}

func responseForm(t *testing.T, doc *etree.Document) string {
	t.Helper()
	data, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"RelayState": {"test-ticket"},
		"SAMLResponse": {base64.StdEncoding.EncodeToString(data)}}.Encode()
}

func requiredElement(t *testing.T, root *etree.Element, path string) *etree.Element {
	t.Helper()
	element := root.FindElement(path)
	if element == nil {
		t.Fatalf("test fixture missing %s", path)
	}
	return element
}

// CVE-2026-33487: the matching reference must not be replaced by the last
// reference in SignedInfo. Our SSO subset refuses multiple references entirely.
// The synthetic IdP signs both references with an
// ephemeral test key; no real IdP credentials are used.
func TestSAMLMultipleReferenceIntegrity(t *testing.T) {
	signer, md := testIdP(t)
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprintf("tamper=%v", tamper), func(t *testing.T) {
			a, commands := testApp(t, md)
			// Both names pass the allowlist, so only signature validation can reject
			// the substituted subject in this regression test.
			a.config.AllowedSubjects = append(a.config.AllowedSubjects, "substituted-user")
			doc := responseDocument(t, responseBody(t, a, signer, assertionFor(a), false, false))
			root := doc.Root()
			ctx, err := saml.GetSigningContext(signer)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := ctx.ConstructSignature(root, true)
			if err != nil {
				t.Fatal(err)
			}
			si := requiredElement(t, signature, "./SignedInfo")
			other := root.Copy()
			requiredElement(t, other, "./Assertion/Subject/NameID").SetText("substituted-user")
			otherSignature, err := ctx.ConstructSignature(other, true)
			if err != nil {
				t.Fatal(err)
			}
			lastReference := requiredElement(t, otherSignature, "./SignedInfo/Reference").Copy()
			lastReference.CreateAttr("URI", "#unrelated")
			si.AddChild(lastReference)
			root.AddChild(signature)
			canonical, err := ctx.Canonicalizer.Canonicalize(si)
			if err != nil {
				t.Fatal(err)
			}
			hash := ctx.Hash.New()
			hash.Write(canonical)
			signed, err := signer.Key.Sign(rand.Reader, hash.Sum(nil), ctx.Hash)
			if err != nil {
				t.Fatal(err)
			}
			requiredElement(t, signature, "./SignatureValue").SetText(base64.StdEncoding.EncodeToString(signed))
			if tamper {
				requiredElement(t, root, "./Assertion/Subject/NameID").SetText("substituted-user")
			}
			w := submit(a, responseForm(t, doc), "test-browser")
			if w.Code != http.StatusForbidden || a.connections[7].active || len(commands) != 0 {
				t.Fatal("multiple references must be refused by the SSO subset")
			}
		})
	}
}

// Exercise the real ACS with a valid pending login, so cookie/request checks do
// not accidentally hide XML parser regressions.
func TestSAMLExcessiveXMLRefusedBeforeAuthorization(t *testing.T) {
	signer, md := testIdP(t)
	for _, name := range []string{"deep-signed-info", "wide-signed-info", "text-fragments", "invalid-base64"} {
		t.Run(name, func(t *testing.T) {
			a, commands := testApp(t, md)
			validBody := responseBody(t, a, signer, assertionFor(a), true, false)
			doc := responseDocument(t, validBody)
			si := requiredElement(t, doc.Root(), "./Signature/SignedInfo")
			switch name {
			case "deep-signed-info":
				for i := 0; i < 100; i++ {
					si = si.CreateElement("padding")
				}
			case "wide-signed-info":
				for i := 0; i < 1000; i++ {
					si.CreateElement("padding")
				}
			case "text-fragments":
				for i := 0; i < 5000; i++ {
					si.CreateCharData("x")
					si.CreateComment("")
				}
			}
			body := responseForm(t, doc)
			if name == "invalid-base64" {
				body = "RelayState=test-ticket&SAMLResponse=!"
			}
			if submit(a, body, "test-browser").Code != http.StatusForbidden ||
				a.connections[7].active || len(commands) != 0 {
				t.Fatal("invalid XML authorized a connection")
			}
			if submit(a, validBody, "test-browser").Code != http.StatusOK {
				t.Fatal("valid login no longer works after rejecting invalid XML")
			}
		})
	}
}
