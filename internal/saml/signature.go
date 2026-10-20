// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"github.com/beevik/etree"
	"strings"
	"time"
)

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
const digestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
const envelopedSignature = dsNamespace + "enveloped-signature"

func decode64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errSAML
	}
	return b, nil
}
func c14nParameters(e *etree.Element) (string, error) {
	if attribute(e, "Algorithm") != exclusiveC14N {
		return "", errSAML
	}
	if err := onlyChildren(e, allowed(exclusiveC14N, "InclusiveNamespaces")); err != nil {
		return "", err
	}
	cs := children(e, exclusiveC14N, "InclusiveNamespaces")
	if len(cs) == 0 {
		return "", nil
	}
	if len(cs[0].ChildElements()) != 0 {
		return "", errSAML
	}
	return attribute(cs[0], "PrefixList"), nil
}

// verifySignature requires one reference to this exact element. There is no
// document-wide ID lookup, URI dereferencing, implicit transform or fallback
// algorithm. Keys come exclusively from configured IdP metadata.
func verifySignature(e *etree.Element, certs []*x509.Certificate) (*etree.Element, error) {
	sig, err := one(e, dsNamespace, "Signature")
	if err != nil {
		return nil, err
	}
	if err := onlyChildren(sig, allowed(dsNamespace, "SignedInfo", "SignatureValue", "KeyInfo")); err != nil {
		return nil, err
	}
	si, err := one(sig, dsNamespace, "SignedInfo")
	if err != nil {
		return nil, err
	}
	if err := onlyChildren(si, allowed(dsNamespace, "CanonicalizationMethod", "SignatureMethod", "Reference")); err != nil {
		return nil, err
	}
	method, err := one(si, dsNamespace, "SignatureMethod")
	if err != nil || attribute(method, "Algorithm") != rsaSHA256 || len(method.ChildElements()) != 0 {
		return nil, errSAML
	}
	cm, err := one(si, dsNamespace, "CanonicalizationMethod")
	if err != nil {
		return nil, err
	}
	prefixes, err := c14nParameters(cm)
	if err != nil {
		return nil, err
	}
	ref, err := one(si, dsNamespace, "Reference")
	if err != nil || attribute(e, "ID") == "" || attribute(ref, "URI") != "#"+attribute(e, "ID") {
		return nil, errSAML
	}
	if err := onlyChildren(ref, allowed(dsNamespace, "Transforms", "DigestMethod", "DigestValue")); err != nil {
		return nil, err
	}
	transforms, err := one(ref, dsNamespace, "Transforms")
	if err != nil {
		return nil, err
	}
	ts := transforms.ChildElements()
	if len(ts) != 2 || !named(ts[0], dsNamespace, "Transform") || !named(ts[1], dsNamespace, "Transform") ||
		attribute(ts[0], "Algorithm") != envelopedSignature || len(ts[0].ChildElements()) != 0 {
		return nil, errSAML
	}
	rp, err := c14nParameters(ts[1])
	if err != nil {
		return nil, err
	}
	dm, err := one(ref, dsNamespace, "DigestMethod")
	if err != nil || attribute(dm, "Algorithm") != digestSHA256 || len(dm.ChildElements()) != 0 {
		return nil, errSAML
	}
	dv, err := one(ref, dsNamespace, "DigestValue")
	if err != nil {
		return nil, err
	}
	digestText, err := textValue(dv)
	if err != nil {
		return nil, err
	}
	expected, err := decode64(digestText)
	if err != nil || len(expected) != sha256.Size {
		return nil, errSAML
	}
	canonical, err := canonicalize(e, sig, rp)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	if subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
		return nil, errSAML
	}
	signed, err := canonicalize(si, nil, prefixes)
	if err != nil {
		return nil, err
	}
	sv, err := one(sig, dsNamespace, "SignatureValue")
	if err != nil {
		return nil, err
	}
	signatureText, err := textValue(sv)
	if err != nil {
		return nil, err
	}
	signature, err := decode64(signatureText)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(signed)
	now := time.Now()
	for _, cert := range certs {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			continue
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			continue
		}
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], signature) == nil {
			// Authorization consumes the exact canonical bytes whose digest we checked,
			// with comments and this signature removed, never the unverified input tree.
			return parseXML(canonical)
		}
	}
	return nil, errSAML
}
