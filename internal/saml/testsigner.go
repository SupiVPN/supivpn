// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/beevik/etree"
)

// SigningContext supports synthetic IdPs in the test suite. Runtime AuthnRequests
// are unsigned; this is not a general-purpose XML signing API.
type SigningContext struct {
	Hash          crypto.Hash
	Canonicalizer testCanonicalizer
	sp            *ServiceProvider
}
type testCanonicalizer struct{}

func (testCanonicalizer) Canonicalize(e *etree.Element) ([]byte, error) {
	return canonicalize(e, nil, "")
}
func GetSigningContext(sp *ServiceProvider) (*SigningContext, error) {
	if sp.Key == nil || sp.Certificate == nil || sp.SignatureMethod != rsaSHA256 {
		return nil, errSAML
	}
	return &SigningContext{Hash: crypto.SHA256, sp: sp}, nil
}
func (ctx *SigningContext) ConstructSignature(e *etree.Element, enveloped bool) (*etree.Element, error) {
	if !enveloped || attribute(e, "ID") == "" {
		return nil, errSAML
	}
	canonical, err := canonicalize(e, nil, "")
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(canonical)
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", dsNamespace)
	si := sig.CreateElement("ds:SignedInfo")
	si.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", exclusiveC14N)
	si.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", rsaSHA256)
	ref := si.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+attribute(e, "ID"))
	ts := ref.CreateElement("ds:Transforms")
	ts.CreateElement("ds:Transform").CreateAttr("Algorithm", envelopedSignature)
	ts.CreateElement("ds:Transform").CreateAttr("Algorithm", exclusiveC14N)
	ref.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestSHA256)
	ref.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(hash[:]))
	signed, err := canonicalize(si, nil, "")
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signed)
	signature, err := ctx.sp.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	sig.CreateElement("ds:SignatureValue").SetText(base64.StdEncoding.EncodeToString(signature))
	sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(ctx.sp.Certificate.Raw))
	return sig, nil
}
func (ctx *SigningContext) SignEnveloped(e *etree.Element) (*etree.Element, error) {
	copy := e.Copy()
	scope, err := parentNS(e)
	if err != nil {
		return nil, err
	}
	for prefix, uri := range scope {
		if prefix == "xml" {
			continue
		}
		name := "xmlns"
		if prefix != "" {
			name += ":" + prefix
		}
		if copy.SelectAttr(name) == nil {
			copy.CreateAttr(name, uri)
		}
	}
	sig, err := ctx.ConstructSignature(copy, true)
	if err != nil {
		return nil, err
	}
	// The SAML schema places Signature directly after Issuer.
	index := 0
	for _, c := range copy.ChildElements() {
		if named(c, AssertionNamespace, "Issuer") {
			index = c.Index() + 1
			break
		}
	}
	copy.InsertChildAt(index, sig)
	return copy, nil
}
