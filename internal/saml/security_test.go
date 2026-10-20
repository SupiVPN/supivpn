// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// Mutate BEFORE signing: a bad digest must not hide missing semantic checks.
func TestSecuritySignedAssertionShape(t *testing.T) {
	sp, signer, base := fixture(t)
	cases := map[string]func(*etree.Element){
		"duplicate-subject": func(a *etree.Element) {
			a.AddChild(a.FindElement("./Subject").Copy())
		},
		"duplicate-name-id": func(a *etree.Element) {
			s := a.FindElement("./Subject")
			s.AddChild(s.FindElement("./NameID").Copy())
		},
		"duplicate-conditions": func(a *etree.Element) {
			a.AddChild(a.FindElement("./Conditions").Copy())
		},
		"unknown-condition": func(a *etree.Element) {
			a.FindElement("./Conditions").CreateElement("a:ProxyRestriction")
		},
		"ambiguous-audience": func(a *etree.Element) {
			r := a.FindElement("./Conditions/AudienceRestriction")
			r.AddChild(r.FindElement("./Audience").Copy())
		},
		"complex-name-id": func(a *etree.Element) {
			a.FindElement("./Subject/NameID").CreateElement("a:NameID").SetText("other")
		},
		"complex-bearer-data": func(a *etree.Element) {
			a.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData").CreateElement("a:NameID").SetText("other")
		},
		"foreign-group-element": func(a *etree.Element) {
			v := a.FindElement("./AttributeStatement/Attribute/AttributeValue")
			v.CreateElement("p:NameID").SetText("admins-vpn")
		},
		"nil-group": func(a *etree.Element) {
			v := a.FindElement("./AttributeStatement/Attribute/AttributeValue")
			v.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
			v.CreateAttr("xsi:nil", "true")
		},
	}
	for _, mode := range []string{"response", "assertion", "both"} {
		t.Run(mode, func(t *testing.T) {
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					root := base.Copy()
					mutate(root.FindElement("./Assertion"))
					root = signedFixture(t, signer, root, mode)
					verified := root
					var err error
					if mode != "assertion" {
						verified, err = verifySignature(root, []*x509.Certificate{signer.sp.Certificate})
						if err != nil {
							t.Fatal("test requires a cryptographically valid Response")
						}
					}
					if mode != "response" {
						if _, err = verifySignature(verified.FindElement("./Assertion"), []*x509.Certificate{signer.sp.Certificate}); err != nil {
							t.Fatal("test requires a cryptographically valid Assertion")
						}
					}
					if _, err = sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
						t.Fatal("valid signature bypassed assertion shape policy")
					}
				})
			}
		})
	}
}

func TestSecurityMetadataKeyRollover(t *testing.T) {
	sp, oldSigner, base := fixture(t)
	next, newSigner, _ := fixture(t)
	oldKey := sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0]
	newKey := next.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0]
	oldReply := document(t, signedFixture(t, oldSigner, base.Copy(), "response"))
	newReply := document(t, signedFixture(t, newSigner, base.Copy(), "response"))
	for _, tc := range []struct {
		name         string
		keys         []KeyDescriptor
		oldOK, newOK bool
	}{
		{"before", []KeyDescriptor{oldKey}, true, false},
		{"overlap", []KeyDescriptor{oldKey, newKey}, true, true},
		{"after", []KeyDescriptor{newKey}, false, true},
		{"empty", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = tc.keys
			for i, data := range [][]byte{oldReply, newReply} {
				_, err := sp.ParseXMLResponse(data, []string{"_request"}, sp.AcsURL)
				if (err == nil) != []bool{tc.oldOK, tc.newOK}[i] {
					t.Fatal("trust does not follow the configured metadata keys")
				}
			}
		})
	}
	// KeyInfo is outside SignedInfo and excluded from the enveloped digest.
	// Replacing it must neither grant trust nor veto an actually trusted key.
	sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{oldKey}
	for _, tc := range []struct {
		signer     *SigningContext
		advertised KeyDescriptor
		allowed    bool
	}{
		{oldSigner, newKey, true},
		{newSigner, oldKey, false},
	} {
		root := signedFixture(t, tc.signer, base.Copy(), "response")
		root.FindElement("./Signature/KeyInfo/X509Data/X509Certificate").SetText(tc.advertised.KeyInfo.X509Data.X509Certificates[0].Data)
		_, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
		if (err == nil) != tc.allowed {
			t.Fatal("response KeyInfo changed the trust anchor")
		}
	}
}

func TestSecuritySigningCertificatePolicy(t *testing.T) {
	sp, signer, base := fixture(t)
	for _, name := range []string{"valid", "expired", "future", "encryption-only", "weak-rsa", "metadata-encryption-key"} {
		t.Run(name, func(t *testing.T) {
			key := signer.sp.Key.(*rsa.PrivateKey)
			template := *signer.sp.Certificate
			switch name {
			case "expired":
				template.NotBefore, template.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			case "future":
				template.NotBefore, template.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			case "encryption-only":
				template.KeyUsage = x509.KeyUsageKeyEncipherment
			case "weak-rsa":
				var err error
				key, err = rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					t.Fatal(err)
				}
			}
			template.PublicKey = &key.PublicKey
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := GetSigningContext(&ServiceProvider{Key: key, Certificate: cert, SignatureMethod: rsaSHA256})
			if err != nil {
				t.Fatal(err)
			}
			use := "signing"
			if name == "metadata-encryption-key" {
				use = "encryption"
			}
			sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{{
				Use: use, KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}}}},
			}}
			_, err = sp.ParseXMLResponse(document(t, signedFixture(t, ctx, base.Copy(), "response")), []string{"_request"}, sp.AcsURL)
			if (err == nil) != (name == "valid") {
				t.Fatal("signing certificate policy not enforced")
			}
		})
	}
}
