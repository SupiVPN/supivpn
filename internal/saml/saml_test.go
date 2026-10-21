// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/beevik/etree"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fixture(t testing.TB) (*ServiceProvider, *SigningContext, *etree.Element) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := GetSigningContext(&ServiceProvider{Key: key, Certificate: cert, SignatureMethod: rsaSHA256})
	if err != nil {
		t.Fatal(err)
	}
	acs, _ := url.Parse("https://vpn.example.test/saml/acs")
	sp := &ServiceProvider{EntityID: "https://vpn.example.test/saml/metadata", AcsURL: *acs, IDPMetadata: &EntityDescriptor{EntityID: "https://idp.example.test",
		IDPSSODescriptors: []IDPSSODescriptor{{ProtocolSupportEnumeration: ProtocolNamespace,
			KeyDescriptors:       []KeyDescriptor{{Use: "signing", KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}}}}}},
			SingleSignOnServices: []Endpoint{{Binding: HTTPRedirectBinding, Location: "https://idp.example.test/sso"}}}}}}
	now := time.Now().UTC()
	raw := fmt.Sprintf(`<p:Response xmlns:p="%s" xmlns:a="%s" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_response" Version="2.0" InResponseTo="_request" Destination="%s" IssueInstant="%s"><a:Issuer>https://idp.example.test</a:Issuer><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status><a:Assertion ID="_assertion" Version="2.0" IssueInstant="%s"><a:Issuer>https://idp.example.test</a:Issuer><a:Subject><a:NameID>test-user</a:NameID><a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><a:SubjectConfirmationData InResponseTo="_request" Recipient="%s" NotOnOrAfter="%s"/></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore="%s" NotOnOrAfter="%s"><a:AudienceRestriction><a:Audience>%s</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant="%s"><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement><a:AttributeStatement><a:Attribute Name="groups"><a:AttributeValue>admins-vpn</a:AttributeValue></a:Attribute></a:AttributeStatement></a:Assertion></p:Response>`,
		ProtocolNamespace, AssertionNamespace, acs.String(), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), acs.String(),
		now.Add(time.Minute).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Minute).Format(time.RFC3339Nano), sp.EntityID, now.Format(time.RFC3339Nano))
	root, err := parseXML([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sp, signer, root
}
func document(t testing.TB, e *etree.Element) []byte {
	t.Helper()
	d := etree.NewDocument()
	d.SetRoot(e.Copy())
	b, err := d.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func signedFixture(t testing.TB, ctx *SigningContext, root *etree.Element, mode string) *etree.Element {
	t.Helper()
	var err error
	if mode == "assertion" || mode == "both" {
		a, _ := one(root, AssertionNamespace, "Assertion")
		signed, e := ctx.SignEnveloped(a)
		if e != nil {
			t.Fatal(e)
		}
		root.RemoveChild(a)
		root.AddChild(signed)
	}
	if mode == "response" || mode == "both" {
		root, err = ctx.SignEnveloped(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestSignedResponseModes(t *testing.T) {
	sp, ctx, base := fixture(t)
	for _, mode := range []string{"response", "assertion", "both"} {
		t.Run(mode, func(t *testing.T) {
			root := signedFixture(t, ctx, base.Copy(), mode)
			a, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
			if err != nil || a.Subject.NameID.Value != "test-user" || a.AttributeStatements[0].Attributes[0].Values[0].Value != "admins-vpn" {
				t.Fatal("valid signature mode refused")
			}
		})
	}
	// Metadata uses exactly the same trust anchor for verification.
	md, err := xml.Marshal(sp.IDPMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMetadata(md); err != nil {
		t.Fatal("metadata round trip failed")
	}
}
func TestSAMLSignatureBoundaries(t *testing.T) {
	sp, ctx, base := fixture(t)
	cases := map[string]func(*etree.Element){
		"subject-tamper": func(r *etree.Element) { r.FindElement("./Assertion/Subject/NameID").SetText("attacker") },
		"group-tamper": func(r *etree.Element) {
			r.FindElement("./Assertion/AttributeStatement/Attribute/AttributeValue").SetText("attacker-vpn")
		},
		"second-assertion":        func(r *etree.Element) { r.AddChild(r.FindElement("./Assertion").Copy()) },
		"unsigned-assertion-wrap": func(r *etree.Element) { r.FindElement("./Assertion").CreateAttr("xmlns:a", "urn:wrong") },
		"duplicate-id":            func(r *etree.Element) { r.FindElement("./Assertion").CreateAttr("ID", "_response") },
		"external-reference": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/Reference").CreateAttr("URI", "https://invalid.example.test/")
		},
		"other-reference": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/Reference").CreateAttr("URI", "#_assertion")
		},
		"empty-reference": func(r *etree.Element) { r.FindElement("./Signature/SignedInfo/Reference").CreateAttr("URI", "") },
		"multiple-references": func(r *etree.Element) {
			si := r.FindElement("./Signature/SignedInfo")
			si.AddChild(si.FindElement("./Reference").Copy())
		},
		"sha1": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/SignatureMethod").CreateAttr("Algorithm", dsNamespace+"rsa-sha1")
		},
		"ecdsa": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/SignatureMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
		},
		"inclusive-c14n": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/CanonicalizationMethod").CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
		},
		"xpath": func(r *etree.Element) {
			r.FindElement("./Signature/SignedInfo/Reference/Transforms/Transform").CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
		},
		"signature-value": func(r *etree.Element) { r.FindElement("./Signature/SignatureValue").SetText("AA==") },
		"no-signature":    func(r *etree.Element) { r.RemoveChild(r.FindElement("./Signature")) },
		"ambiguous-signed-info": func(r *etree.Element) {
			sig := r.FindElement("./Signature")
			sig.AddChild(sig.FindElement("./SignedInfo").Copy())
		},
		"prefixed-attribute": func(r *etree.Element) { r.CreateAttr("xmlns:evil", "urn:evil"); r.CreateAttr("evil:ID", "_other") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := signedFixture(t, ctx, base.Copy(), "response")
			mutate(root)
			if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	other, _, _ := fixture(t)
	root := signedFixture(t, ctx, base.Copy(), "response")
	if _, err := other.ParseXMLResponse(document(t, root), []string{"_request"}, other.AcsURL); err == nil {
		t.Fatal("KeyInfo supplied an untrusted signing key")
	}
}
func TestCanonicalTextIsAuthorized(t *testing.T) {
	sp, ctx, root := fixture(t)
	name := root.FindElement("./Assertion/Subject/NameID")
	name.SetText("first")
	name.CreateComment("ignored")
	name.CreateCharData("second")
	root = signedFixture(t, ctx, root, "response")
	a, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
	if err != nil || a.Subject.NameID.Value != "firstsecond" {
		t.Fatal("comment split changed authorized subject")
	}
}
func TestExclusiveCanonicalization(t *testing.T) {
	cases := []struct{ input, prefixes, want string }{
		{`<r xmlns="urn:a"><c xmlns=""><d/></c><e/></r>`, "", `<r xmlns="urn:a"><c xmlns=""><d></d></c><e></e></r>`},
		{`<r xmlns:a="urn:a" xmlns:b="urn:b"><a:x/><b:y/><a:z/></r>`, "", `<r><a:x xmlns:a="urn:a"></a:x><b:y xmlns:b="urn:b"></b:y><a:z xmlns:a="urn:a"></a:z></r>`},
		{`<r xmlns:a="urn:a" xmlns:b="urn:b" z="2" a="1"><a:x/></r>`, "b", `<r xmlns:b="urn:b" a="1" z="2"><a:x xmlns:a="urn:a"></a:x></r>`},
		{`<r a="&quot;&amp;&#x9;&#xA;&#xD;">&lt;&amp;&gt;&#xD;<!--gone--><![CDATA[<]]></r>`, "", `<r a="&quot;&amp;&#x9;&#xA;&#xD;">&lt;&amp;&gt;&#xD;&lt;</r>`},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			root, err := parseXML([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalize(root, nil, tc.prefixes)
			if err != nil || string(got) != tc.want {
				t.Fatalf("canonical bytes mismatch: %q", got)
			}
		})
	}
	// Namespace inherited from an unsigned envelope must remain available.
	root, err := parseXML([]byte(`<r xmlns="urn:default" xmlns:a="urn:a" xmlns:q="urn:q"><a:c><d/></a:c></r>`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonicalize(root.ChildElements()[0], nil, "#default q")
	if err != nil || string(got) != `<a:c xmlns="urn:default" xmlns:a="urn:a" xmlns:q="urn:q"><d></d></a:c>` {
		t.Fatalf("ancestor context lost: %q", got)
	}
}

func BenchmarkCanonicalize(b *testing.B) {
	_, _, root := fixture(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := canonicalize(root, nil, ""); err != nil {
			b.Fatal(err)
		}
	}
}
func TestMalformedXMLRefused(t *testing.T) {
	for _, s := range []string{
		`<!DOCTYPE r [<!ENTITY x "value">]><r>&x;</r>`,
		`<r ID="a" ID="b"/>`, `<r xmlns:p="urn:p" xmlns:q="urn:p" p:x="1" q:x="2"/>`,
		`<p:r/>`, `<r xmlns:xml="urn:wrong"/>`, `<r xmlns:p="relative"/>`, `<r/><r/>`,
		`<r><?instruction x?></r>`, `<r xmlns:p="urn:p"><p:x></x></r>`,
		`<r xmlns:p="urn:p" xmlns:q="urn:p"><p:x></q:x></r>`,
		"<r a=\"raw\nnewline\"/>", strings.Repeat("<r>", 65) + strings.Repeat("</r>", 65),
	} {
		if _, err := parseXML([]byte(s)); err == nil {
			t.Fatalf("ambiguous XML accepted: %q", s)
		}
	}
}

func TestMetadataExpirationAtVerification(t *testing.T) {
	sp, ctx, base := fixture(t)
	root := signedFixture(t, ctx, base, "response")
	expired := time.Now().Add(-time.Second)
	sp.IDPMetadata.ValidUntil = &expired
	if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
		t.Fatal("expired metadata accepted after startup")
	}
}

func TestSignedNilClaimRefused(t *testing.T) {
	sp, ctx, root := fixture(t)
	value := root.FindElement("./Assertion/AttributeStatement/Attribute/AttributeValue")
	value.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	value.CreateAttr("xsi:nil", "true")
	root = signedFixture(t, ctx, root, "response")
	if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
		t.Fatal("nil group claim authorized as text")
	}
}
func FuzzSAMLXML(f *testing.F) {
	for _, s := range []string{`<r/>`, `<r xmlns="urn:r"><c/></r>`, `<r ID="a" ID="b"/>`, `<r>&#xD;</r>`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := parseXML(b)
		if err != nil {
			return
		}
		canonical, err := canonicalize(root, nil, "")
		if err != nil {
			return
		}
		// The verifier reparses these bytes before authorizing claims. Check that
		// serialization does not reinterpret the tree, within parser budgets.
		if err := CheckXML(canonical); err != nil {
			return
		}
		reparsed, err := parseXML(canonical)
		if err != nil {
			t.Fatal("canonical output cannot be parsed safely")
		}
		again, err := canonicalize(reparsed, nil, "")
		if err != nil || !bytes.Equal(canonical, again) {
			t.Fatal("exclusive canonicalization is not idempotent")
		}
	})
}
