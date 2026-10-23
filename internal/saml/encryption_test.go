// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func encryptionFixture(t testing.TB) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// Test encryption uses independent standard-library encryption operations; the
// receiver only implements decryption. XMLSec additionally covers the wire format.
func encryptFixture(t testing.TB, root *etree.Element, key *rsa.PublicKey, size int, legacy bool, hash, mgf crypto.Hash) *etree.Element {
	t.Helper()
	assertion := root.FindElement("./Assertion")
	plaintext, err := canonicalize(assertion, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	return encryptBytes(t, root, plaintext, key, size, legacy, hash, mgf)
}
func encryptBytes(t testing.TB, root *etree.Element, plaintext []byte, key *rsa.PublicKey, size int, legacy bool, hash, mgf crypto.Hash) *etree.Element {
	t.Helper()
	cek := make([]byte, size)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	defer clear(cek)
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, key, cek, &rsa.OAEPOptions{Hash: hash, MGFHash: mgf})
	if err != nil {
		t.Fatal(err)
	}
	algorithm := rsaOAEP
	mgfXML := fmt.Sprintf("<x11:MGF Algorithm=%q/>", xenc11Namespace+"mgf1sha256")
	if mgf == crypto.SHA1 {
		mgfXML = fmt.Sprintf("<x11:MGF Algorithm=%q/>", xenc11Namespace+"mgf1sha1")
	}
	if legacy {
		algorithm = rsaOAEP10
		mgfXML = ""
	}
	digest := digestSHA256
	if hash == crypto.SHA1 {
		digest = dsNamespace + "sha1"
	}
	raw := fmt.Sprintf(`<a:EncryptedAssertion xmlns:a="%s" xmlns:x="%s" xmlns:x11="%s" xmlns:ds="%s"><x:EncryptedData Id="_encrypted" Type="%sElement"><x:EncryptionMethod Algorithm="%saes%d-gcm"/><ds:KeyInfo><x:EncryptedKey><x:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/>%s</x:EncryptionMethod><x:CipherData><x:CipherValue>%s</x:CipherValue></x:CipherData></x:EncryptedKey></ds:KeyInfo><x:CipherData><x:CipherValue>%s</x:CipherValue></x:CipherData></x:EncryptedData></a:EncryptedAssertion>`, AssertionNamespace, xencNamespace, xenc11Namespace, dsNamespace, xencNamespace, xenc11Namespace, size*8, algorithm, digest, mgfXML, base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(encrypted))
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	root.RemoveChild(root.FindElement("./Assertion"))
	root.AddChild(doc.Root())
	return root
}
func encryptedResponse(t testing.TB, signer *SigningContext, base *etree.Element, key *rsa.PublicKey, signatures string) *etree.Element {
	t.Helper()
	root := base.Copy()
	if signatures == "assertion" || signatures == "both" {
		root = signedFixture(t, signer, root, "assertion")
	}
	root = encryptFixture(t, root, key, 32, false, crypto.SHA256, crypto.SHA256)
	if signatures == "response" || signatures == "both" {
		root = signedFixture(t, signer, root, "response")
	}
	return root
}

func TestAssertionEncryptionModes(t *testing.T) {
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	for _, mode := range []string{EncryptionDisabled, EncryptionOptional, EncryptionRequired} {
		t.Run(mode, func(t *testing.T) {
			sp.AssertionEncryption = nil
			if mode != EncryptionDisabled {
				var err error
				sp.AssertionEncryption, err = NewAssertionEncryption(mode, key, cert)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, signatures := range []string{"none", "assertion", "response", "both"} {
				t.Run(signatures, func(t *testing.T) {
					plain := signedFixture(t, signer, base.Copy(), signatures)
					encrypted := encryptedResponse(t, signer, base, &key.PublicKey, signatures)
					for i, root := range []*etree.Element{plain, encrypted} {
						result, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
						want := signatures != "none" && ((i == 0 && mode != EncryptionRequired) || (i == 1 && mode != EncryptionDisabled))
						if (err == nil) != want {
							t.Fatalf("mode/signature/format policy failed: format %d", i)
						}
						if err == nil && (result.Subject.NameID.Value != "test-user" || result.AttributeStatements[0].Attributes[0].Values[0].Value != "admins-vpn" || result.Conditions.AudienceRestrictions[0].Audience.Value != sp.EntityID) {
							t.Fatal("decryption changed authenticated claims")
						}
					}
				})
			}
			md, err := xml.Marshal(sp.Metadata())
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseXML(md)
			if err != nil {
				t.Fatal(err)
			}
			count := countLocal(parsed, "KeyDescriptor")
			if (count == 1) != (mode != EncryptionDisabled) {
				t.Fatal("metadata must advertise encryption only when enabled")
			}
			if count == 1 {
				descriptor := parsed.FindElement("./SPSSODescriptor/KeyDescriptor")
				if attribute(descriptor, "use") != "encryption" || descriptor.FindElement("./KeyInfo/X509Data/X509Certificate").Text() != base64.StdEncoding.EncodeToString(cert.Raw) {
					t.Fatal("wrong public encryption certificate")
				}
			}
		})
	}
}
func TestEncryptionAlgorithms(t *testing.T) {
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionRequired, key, cert)
	for _, size := range []int{16, 32} {
		for _, legacy := range []bool{false, true} {
			for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
				for _, mgf := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
					if legacy && mgf != crypto.SHA1 {
						continue
					}
					t.Run(fmt.Sprintf("%d/%t/%s/%s", size, legacy, hash, mgf), func(t *testing.T) {
						root := signedFixture(t, signer, base.Copy(), "assertion")
						root = encryptFixture(t, root, &key.PublicKey, size, legacy, hash, mgf)
						if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err != nil {
							t.Fatal("supported encryption algorithm refused")
						}
						if hash == crypto.SHA1 && mgf == crypto.SHA1 {
							method := root.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod")
							for _, child := range method.ChildElements() {
								method.RemoveChild(child)
							}
							if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err != nil {
								t.Fatal("standard OAEP defaults refused")
							}
						}
					})
				}
			}
		}
	}
}
func TestEncryptionRejectsUnsafeEnvelopes(t *testing.T) {
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionRequired, key, cert)
	cases := map[string]func(*etree.Element){
		"cbc": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/EncryptionMethod").CreateAttr("Algorithm", xencNamespace+"aes256-cbc")
		},
		"rsa-v15": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod").CreateAttr("Algorithm", xencNamespace+"rsa-1_5")
		},
		"unknown-digest": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod/DigestMethod").CreateAttr("Algorithm", dsNamespace+"md5")
		},
		"unknown-mgf": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod/MGF").CreateAttr("Algorithm", "unknown")
		},
		"legacy-mgf": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod").CreateAttr("Algorithm", rsaOAEP10)
		},
		"content-type": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData").CreateAttr("Type", xencNamespace+"Content")
		},
		"key-size": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/EncryptionMethod").CreateElement("x:KeySize").SetText("128")
		},
		"wrong-recipient": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey").CreateAttr("Recipient", "https://other.example.test")
		},
		"gcm-tag": func(r *etree.Element) {
			v := r.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue")
			b, _ := decode64(v.Text())
			b[len(b)-1] ^= 1
			v.SetText(base64.StdEncoding.EncodeToString(b))
		},
		"nonce": func(r *etree.Element) {
			v := r.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue")
			b, _ := decode64(v.Text())
			b[0] ^= 1
			v.SetText(base64.StdEncoding.EncodeToString(b))
		},
		"truncated": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue").SetText(base64.StdEncoding.EncodeToString(make([]byte, 28)))
		},
		"wrapped-key": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue").SetText("AA==")
		},
		"cipher-reference": func(r *etree.Element) {
			d := r.FindElement("./EncryptedAssertion/EncryptedData/CipherData")
			d.RemoveChild(d.FindElement("./CipherValue"))
			d.CreateElement("x:CipherReference").CreateAttr("URI", "https://invalid.example.test/cipher")
		},
		"retrieval-method": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo").CreateElement("ds:RetrievalMethod").CreateAttr("URI", "https://invalid.example.test/key")
		},
		"second-encrypted": func(r *etree.Element) { r.AddChild(r.FindElement("./EncryptedAssertion").Copy()) },
		"mixed-plain":      func(r *etree.Element) { r.AddChild(base.FindElement("./Assertion").Copy()) },
		"hidden-signature": func(r *etree.Element) {
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey").CreateElement("ds:Signature")
		},
		"duplicate-method": func(r *etree.Element) {
			e := r.FindElement("./EncryptedAssertion/EncryptedData")
			e.AddChild(e.FindElement("./EncryptionMethod").Copy())
		},
		"duplicate-data": func(r *etree.Element) {
			e := r.FindElement("./EncryptedAssertion")
			e.AddChild(e.FindElement("./EncryptedData").Copy())
		},
		"wrong-namespace": func(r *etree.Element) { r.FindElement("./EncryptedAssertion").CreateAttr("xmlns:x", "urn:wrong") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := encryptedResponse(t, signer, base, &key.PublicKey, "assertion")
			mutate(root)
			// A valid outer signature cannot rescue invalid encryption or structure.
			root = signedFixture(t, signer, root, "response")
			if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
				t.Fatal("unsafe encryption accepted")
			}
		})
	}
	other, _ := encryptionFixture(t)
	wrong := encryptedResponse(t, signer, base, &other.PublicKey, "both")
	if _, err := sp.ParseXMLResponse(document(t, wrong), []string{"_request"}, sp.AcsURL); err == nil {
		t.Fatal("wrong recipient key accepted")
	}
}
func TestEncryptedAssertionStillRequiresValidSignaturesAndShape(t *testing.T) {
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionRequired, key, cert)
	for _, name := range []string{"bad-inner-signature", "untrusted-inner", "duplicate-inner", "cross-document-id", "hidden-inner", "wrong-issuer", "wrong-correlation", "bad-outer-signature", "nested-encryption", "malformed-plaintext", "oversized-plaintext"} {
		t.Run(name, func(t *testing.T) {
			root := base.Copy()
			a := root.FindElement("./Assertion")
			switch name {
			case "duplicate-inner":
				a.AddChild(a.FindElement("./Subject").Copy())
			case "cross-document-id":
				a.CreateAttr("ID", "_response")
			case "hidden-inner":
				a.FindElement("./AttributeStatement").AddChild(a.Copy())
			case "wrong-issuer":
				a.FindElement("./Issuer").SetText("https://other.example.test")
			case "wrong-correlation":
				root.CreateAttr("InResponseTo", "_other")
			case "nested-encryption":
				a.CreateElement("a:EncryptedAssertion")
			}
			ctx := signer
			if name == "untrusted-inner" {
				_, ctx, _ = fixture(t)
			}
			root = signedFixture(t, ctx, root, "assertion")
			if name == "bad-inner-signature" {
				root.FindElement("./Assertion/Signature/SignatureValue").SetText("AA==")
			}
			switch name {
			case "malformed-plaintext":
				root = encryptBytes(t, root, []byte("<broken"), &key.PublicKey, 32, false, crypto.SHA256, crypto.SHA256)
			case "oversized-plaintext":
				root = encryptBytes(t, root, make([]byte, maxXMLBytes+1), &key.PublicKey, 32, false, crypto.SHA256, crypto.SHA256)
			default:
				root = encryptFixture(t, root, &key.PublicKey, 32, false, crypto.SHA256, crypto.SHA256)
			}
			root = signedFixture(t, signer, root, "response")
			if name == "bad-outer-signature" {
				root.FindElement("./Signature/SignatureValue").SetText("AA==")
			}
			if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
				t.Fatal("encrypted assertion bypassed authentication")
			}
		})
	}
}
