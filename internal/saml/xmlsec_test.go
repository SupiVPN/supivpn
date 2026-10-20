// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestXMLSecInteroperability(t *testing.T) {
	binary := os.Getenv("SUPIVPN_TEST_XMLSEC")
	if binary == "" {
		t.Skip("set SUPIVPN_TEST_XMLSEC to run independent XMLSec checks")
	}
	sp, signer, base := fixture(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write := func(path string, b []byte) {
		t.Helper()
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("cannot write ephemeral fixture")
		}
	}
	write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.sp.Certificate.Raw}))
	write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer.sp.Key.(*rsa.PrivateKey))}))
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// XMLSec diagnostics may include assertion contents. Never copy them to logs.
		if err := exec.CommandContext(ctx, binary, args...).Run(); err != nil {
			t.Fatal("independent XMLSec operation failed")
		}
	}
	for _, mode := range []string{"response", "assertion", "inclusive-prefixes", "default-namespace", "prefix-rebinding", "text-boundaries"} {
		t.Run(mode, func(t *testing.T) {
			signingMode := mode
			if mode != "assertion" {
				signingMode = "response"
			}
			unsigned := base.Copy()
			switch mode {
			case "default-namespace":
				assertion := unsigned.FindElement("./Assertion")
				assertion.CreateAttr("xmlns", AssertionNamespace)
				var unprefix func(*etree.Element)
				unprefix = func(e *etree.Element) {
					e.Space = ""
					for _, child := range e.ChildElements() {
						unprefix(child)
					}
				}
				unprefix(assertion)
			case "prefix-rebinding":
				// An ancestor prefix can mean something different in a child.
				unsigned.CreateAttr("xmlns:q", "urn:unused:ancestor")
				statement := unsigned.FindElement("./Assertion/AttributeStatement")
				statement.CreateAttr("xmlns:q", AssertionNamespace)
				for _, child := range statement.ChildElements() {
					child.Space = "q"
					for _, value := range child.ChildElements() {
						value.Space = "q"
					}
				}
			case "text-boundaries":
				name := unsigned.FindElement("./Assertion/Subject/NameID")
				name.SetText("test-")
				name.CreateComment("not part of the signed canonical text")
				name.CreateCharData("user")
				attr := unsigned.FindElement("./Assertion/AttributeStatement/Attribute")
				attr.CreateAttr("FriendlyName", "VPN \"groups\" & \u043a\u043e\u0440\u0438\u0441\u0442\u0443\u0432\u0430\u0447\u0456")
				attr.CreateAttr("xml:lang", "uk")
			}
			root := signedFixture(t, signer, unsigned, signingMode)
			ownPath, externalPath := filepath.Join(dir, mode+"-ours.xml"), filepath.Join(dir, mode+"-xmlsec.xml")
			write(ownPath, document(t, root))
			// XMLSec independently verifies our digest, canonicalization and RSA signature.
			run("--verify", "--pubkey-cert-pem", certPath, "--id-attr:ID", "Response", "--id-attr:ID", "Assertion", ownPath)
			sig := root.FindElement("./Signature")
			if mode == "assertion" {
				sig = root.FindElement("./Assertion/Signature")
			}
			if mode == "inclusive-prefixes" {
				for _, path := range []string{"./SignedInfo/CanonicalizationMethod", "./SignedInfo/Reference/Transforms/Transform[2]"} {
					e := sig.FindElement(path)
					if e == nil {
						t.Fatal("missing canonicalization fixture")
					}
					inc := e.CreateElement("ec:InclusiveNamespaces")
					inc.CreateAttr("xmlns:ec", exclusiveC14N)
					inc.CreateAttr("PrefixList", "a p xs #default")
				}
			}
			sig.FindElement("./SignatureValue").SetText("")
			sig.FindElement("./SignedInfo/Reference/DigestValue").SetText("")
			write(ownPath, document(t, root))
			// XMLSec fills digest/signature itself, using its libxml2 canonicalizer.
			run("--sign", "--privkey-pem", keyPath+","+certPath, "--id-attr:ID", "Response", "--id-attr:ID", "Assertion", "--output", externalPath, ownPath)
			external, err := os.ReadFile(externalPath)
			if err != nil {
				t.Fatal("cannot read XMLSec fixture")
			}
			if err := CheckXML(external); err != nil {
				t.Fatal("XMLSec output failed streaming bounds")
			}
			parsed, err := parseXML(external)
			if err != nil {
				t.Fatal("XMLSec output failed namespace/ID checks:", err)
			}
			target := parsed
			if mode == "assertion" {
				target = parsed.FindElement("./Assertion")
			}
			if _, err := verifySignature(target, []*x509.Certificate{signer.sp.Certificate}); err != nil {
				t.Fatal("XMLSec output failed signature verification")
			}
			a, err := sp.ParseXMLResponse(external, []string{"_request"}, sp.AcsURL)
			if err != nil || a.Subject.NameID.Value != "test-user" {
				t.Fatal("XMLSec signature rejected")
			}
			// The independently generated signature must not verify altered claims.
			for _, path := range []string{"./Assertion/Subject/NameID", "./Assertion/AttributeStatement/Attribute/AttributeValue"} {
				tampered := parsed.Copy()
				tampered.FindElement(path).SetText("attacker")
				if _, err := sp.ParseXMLResponse(document(t, tampered), []string{"_request"}, sp.AcsURL); err == nil {
					t.Fatal("altered XMLSec-signed claim accepted")
				}
			}
		})
	}
}
