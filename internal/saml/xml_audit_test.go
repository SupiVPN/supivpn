// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

func auditPrefixList(count int) string {
	var prefixes strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&prefixes, "unused%d ", i)
	}
	return prefixes.String()
}

func BenchmarkXMLAuditUntrustedPrefixList(b *testing.B) {
	sp, signer, root := fixture(b)
	attribute := root.FindElement("./Assertion/AttributeStatement/Attribute")
	for i := 0; i < 440; i++ {
		attribute.CreateElement("a:AttributeValue").SetText("member")
	}
	root = signedFixture(b, signer, root, "response")
	for _, count := range []int{0, 50000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			candidate := root.Copy()
			transform := candidate.FindElement("./Signature/SignedInfo/Reference/Transforms/Transform[2]")
			inc := transform.CreateElement("ec:InclusiveNamespaces")
			inc.CreateAttr("xmlns:ec", exclusiveC14N)
			inc.CreateAttr("PrefixList", auditPrefixList(count))
			data := document(b, candidate)
			if err := CheckXML(data); err != nil {
				b.Fatal("benchmark fixture must fit the streaming XML limits")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := sp.ParseXMLResponse(data, []string{"_request"}, sp.AcsURL); err == nil {
					b.Fatal("modified SignedInfo must not authenticate")
				}
			}
		})
	}
}

func TestXMLAuditInclusivePrefixBudget(t *testing.T) {
	for _, count := range []int{0, 1, 64, 65, 50000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root := etree.NewElement("root")
			_, err := canonicalize(root, nil, auditPrefixList(count))
			if (err == nil) != (count <= 64) {
				t.Fatal("inclusive namespace processing is not bounded")
			}
		})
	}
}

func TestXMLAuditCanonicalLeafBudget(t *testing.T) {
	// XML permits literal double quotes in a single-quoted attribute; canonical
	// XML must encode each as &quot;. A leaf has no child-loop budget checks.
	input := []byte(`<root value='` + strings.Repeat(`"`, 4*maxXMLBytes/6+1) + `'/>`)
	root, err := parseXML(input)
	if err != nil {
		t.Fatal("fixture must fit the original XML budgets")
	}
	if _, err := canonicalize(root, nil, ""); err == nil {
		t.Fatal("oversized canonical leaf was accepted")
	}
}

func TestXMLAuditUntrustedConstructs(t *testing.T) {
	cases := map[string]string{
		"external-general-entity":   `<!DOCTYPE root [<!ENTITY remote SYSTEM "https://invalid.example.test/entity">]><root>&remote;</root>`,
		"external-parameter-entity": `<!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///nonexistent-supivpn-fixture">%remote;]><root/>`,
		"external-subset":           `<!DOCTYPE root SYSTEM "https://invalid.example.test/schema"><root/>`,
		"internal-entity":           `<!DOCTYPE root [<!ENTITY value "claim">]><root>&value;</root>`,
		"undeclared-entity":         `<root>&remote;</root>`,
		"xml-stylesheet":            `<?xml-stylesheet href="https://invalid.example.test/style"?><root/>`,
		"late-xml-declaration":      `<root><?xml version="1.0"?></root>`,
		"alias-duplicate-attribute": `<root xmlns:x="http://www.w3.org/2001/XMLSchema-instance" xmlns:y="http://www.w3.org/2001/XMLSchema-instance" x:type="string" y:type="anyType"/>`,
		"duplicate-namespace":       `<root xmlns:x="urn:one" xmlns:x="urn:two"/>`,
		"namespace-prefix-mismatch": `<root xmlns:x="urn:same" xmlns:y="urn:same"><x:value></y:value></root>`,
		"xml-prefix-alias":          `<root xmlns:x="http://www.w3.org/XML/1998/namespace"/>`,
		"xml-base":                  `<root xml:base="https://invalid.example.test/"/>`,
		"xml-id-alias":              `<root xml:id="_claim"/>`,
		"case-variant-id-collision": `<root ID="_claim"><child Id="_claim"/></root>`,
		"prefixed-protocol-field":   `<root xmlns:x="urn:foreign" x:ID="_claim"/>`,
		"trailing-root":             `<root/><other/>`,
		"trailing-content":          `<root/>claim`,
		"non-utf8-encoding":         `<?xml version="1.0" encoding="ISO-8859-1"?><root/>`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseXML([]byte(input)); err == nil {
				t.Fatal("XML outside the supported authentication subset was accepted")
			}
		})
	}
}

func TestXMLAuditSignedRepresentationInvariants(t *testing.T) {
	sp, signer, base := fixture(t)
	for _, mode := range []string{"response", "assertion", "both"} {
		t.Run(mode, func(t *testing.T) {
			root := signedFixture(t, signer, base.Copy(), mode)
			raw := document(t, root)
			for name, candidate := range map[string][]byte{
				"comment-split":        bytes.ReplaceAll(raw, []byte("test-user"), []byte("test-<!--ignored-->user")),
				"cdata-split":          bytes.ReplaceAll(raw, []byte("test-user"), []byte("test-<![CDATA[user]]>")),
				"character-reference":  bytes.ReplaceAll(raw, []byte("admins-vpn"), []byte("admins&#x2D;vpn")),
				"irrelevant-namespace": bytes.Replace(raw, []byte("<p:Response "), []byte(`<p:Response xmlns:unused="urn:unused" `), 1),
			} {
				t.Run(name, func(t *testing.T) {
					assertion, err := sp.ParseXMLResponse(candidate, []string{"_request"}, sp.AcsURL)
					if err != nil || assertion.Subject.NameID.Value != "test-user" ||
						assertion.AttributeStatements[0].Attributes[0].Values[0].Value != "admins-vpn" {
						t.Fatal("equivalent XML representation changed verified claims")
					}
				})
			}
			for name, edit := range map[string]func(*etree.Element){
				"signature-wrapper": func(r *etree.Element) {
					target := r
					if mode == "assertion" {
						target = r.FindElement("./Assertion")
					}
					signature := target.FindElement("./Signature")
					target.RemoveChild(signature)
					target.CreateElement("wrapper").AddChild(signature)
				},
				"assertion-wrapper": func(r *etree.Element) {
					assertion := r.FindElement("./Assertion")
					r.RemoveChild(assertion)
					r.CreateElement("wrapper").AddChild(assertion)
				},
				"group-namespace": func(r *etree.Element) {
					r.FindElement("./Assertion/AttributeStatement/Attribute/AttributeValue").CreateAttr("xmlns:a", "urn:foreign")
				},
				"subject-truncation": func(r *etree.Element) {
					name := r.FindElement("./Assertion/Subject/NameID")
					name.SetText("test-")
					name.CreateComment("user")
				},
				"case-variant-id": func(r *etree.Element) {
					r.FindElement("./Assertion").CreateAttr("id", "_response")
				},
			} {
				t.Run(name, func(t *testing.T) {
					candidate := root.Copy()
					edit(candidate)
					if _, err := sp.ParseXMLResponse(document(t, candidate), []string{"_request"}, sp.AcsURL); err == nil {
						t.Fatal("modified or wrapped authenticated content was accepted")
					}
				})
			}
		})
	}
}
