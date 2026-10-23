// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"testing"

	"github.com/beevik/etree"
)

func TestPeerEncryptionRejectsAmbiguousReferences(t *testing.T) {
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionRequired, key, cert)
	const retrieval = "./EncryptedAssertion/EncryptedData/KeyInfo/RetrievalMethod"
	const peer = "./EncryptedAssertion/EncryptedKey"
	cases := map[string]func(*etree.Element){
		"external-key":              func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("URI", "https://invalid.example.test/key") },
		"wrong-key":                 func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("URI", "#_other_key") },
		"empty-key-reference":       func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("URI", "") },
		"encoded-key-reference":     func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("URI", "#%5frecipient_key") },
		"missing-key-id":            func(r *etree.Element) { r.FindElement(peer).RemoveAttr("Id") },
		"wrong-reference-type":      func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("Type", xencNamespace+"EncryptedData") },
		"missing-reference-type":    func(r *etree.Element) { r.FindElement(retrieval).RemoveAttr("Type") },
		"retrieval-transforms":      func(r *etree.Element) { r.FindElement(retrieval).CreateElement("ds:Transforms") },
		"retrieval-text":            func(r *etree.Element) { r.FindElement(retrieval).SetText("unexpected") },
		"missing-retrieval":         func(r *etree.Element) { e := r.FindElement(retrieval); e.Parent().RemoveChild(e) },
		"duplicate-retrieval":       func(r *etree.Element) { e := r.FindElement(retrieval); e.Parent().AddChild(e.Copy()) },
		"wrong-retrieval-namespace": func(r *etree.Element) { r.FindElement(retrieval).CreateAttr("xmlns:ds", "urn:wrong") },
		"missing-reverse-reference": func(r *etree.Element) { e := r.FindElement(peer + "/ReferenceList"); e.Parent().RemoveChild(e) },
		"wrong-reverse-reference": func(r *etree.Element) {
			r.FindElement(peer+"/ReferenceList/DataReference").CreateAttr("URI", "#_other_data")
		},
		"external-reverse-reference": func(r *etree.Element) {
			r.FindElement(peer+"/ReferenceList/DataReference").CreateAttr("URI", "https://invalid.example.test/data")
		},
		"missing-data-id": func(r *etree.Element) { r.FindElement("./EncryptedAssertion/EncryptedData").RemoveAttr("Id") },
		"duplicate-reverse-reference": func(r *etree.Element) {
			e := r.FindElement(peer + "/ReferenceList/DataReference")
			e.Parent().AddChild(e.Copy())
		},
		"duplicate-key": func(r *etree.Element) {
			e := r.FindElement(peer).Copy()
			e.CreateAttr("Id", "_another_key")
			r.FindElement("./EncryptedAssertion").AddChild(e)
		},
		"inline-and-peer": func(r *etree.Element) {
			e := r.FindElement(peer).Copy()
			e.CreateAttr("Id", "_inline_key")
			r.FindElement("./EncryptedAssertion/EncryptedData/KeyInfo").AddChild(e)
		},
		"key-outside-wrapper": func(r *etree.Element) {
			e := r.FindElement(peer)
			e.Parent().RemoveChild(e)
			e.CreateAttr("xmlns:x", xencNamespace)
			e.CreateAttr("xmlns:ds", dsNamespace)
			e.CreateAttr("xmlns:x11", xenc11Namespace)
			r.AddChild(e)
		},
		"duplicate-cross-document-id": func(r *etree.Element) {
			r.FindElement(peer).CreateAttr("Id", "_response")
			r.FindElement(retrieval).CreateAttr("URI", "#_response")
		},
		"key-id-matches-decrypted-assertion": func(r *etree.Element) {
			id := attribute(base.FindElement("./Assertion"), "ID")
			r.FindElement(peer).CreateAttr("Id", id)
			r.FindElement(retrieval).CreateAttr("URI", "#"+id)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := peerEncryptionKey(encryptedResponse(t, signer, base, &key.PublicKey, "assertion"))
			mutate(root)
			// A trusted outer signature must not make unsafe references acceptable.
			root = signedFixture(t, signer, root, "response")
			if _, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err == nil {
				t.Fatal("unsafe peer key reference accepted")
			}
		})
	}
}
