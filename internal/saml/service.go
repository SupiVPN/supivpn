// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"github.com/beevik/etree"
	"net/url"
	"strings"
	"time"
)

type ServiceProvider struct {
	EntityID            string
	MetadataURL, AcsURL url.URL
	IDPMetadata         *EntityDescriptor
	AuthnNameIDFormat   string
	AllowIDPInitiated   bool
	AssertionEncryption *AssertionEncryption
	// Synthetic IdP fixtures only; SupiVPN never needs an SP signing key.
	Key             crypto.Signer
	Certificate     *x509.Certificate
	SignatureMethod string
}

func ParseMetadata(data []byte) (*EntityDescriptor, error) {
	root, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if !named(root, MetadataNamespace, "EntityDescriptor") {
		return nil, errSAML
	}
	var md EntityDescriptor
	if xml.Unmarshal(data, &md) != nil || md.EntityID == "" || len(md.IDPSSODescriptors) != 1 {
		return nil, errSAML
	}
	if md.ValidUntil != nil && !time.Now().Before(*md.ValidUntil) {
		return nil, errSAML
	}
	if !strings.Contains(" "+md.IDPSSODescriptors[0].ProtocolSupportEnumeration+" ", " "+ProtocolNamespace+" ") {
		return nil, errSAML
	}
	sp := ServiceProvider{IDPMetadata: &md}
	u, err := url.Parse(sp.GetSSOBindingLocation(HTTPRedirectBinding))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errSAML
	}
	if certs, err := sp.certificates(); err != nil || len(certs) == 0 {
		return nil, errSAML
	}
	return &md, nil
}
func (sp *ServiceProvider) certificates() ([]*x509.Certificate, error) {
	if sp.IDPMetadata == nil || (sp.IDPMetadata.ValidUntil != nil && !time.Now().Before(*sp.IDPMetadata.ValidUntil)) {
		return nil, errSAML
	}
	var certs []*x509.Certificate
	for _, idp := range sp.IDPMetadata.IDPSSODescriptors {
		for _, key := range idp.KeyDescriptors {
			if key.Use != "" && key.Use != "signing" {
				continue
			}
			for _, c := range key.KeyInfo.X509Data.X509Certificates {
				der, err := decode64(c.Data)
				if err != nil {
					return nil, err
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, errSAML
				}
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) > 16 {
		return nil, errSAML
	}
	return certs, nil
}
func (sp *ServiceProvider) GetSSOBindingLocation(binding string) string {
	if sp.IDPMetadata != nil {
		for _, idp := range sp.IDPMetadata.IDPSSODescriptors {
			for _, s := range idp.SingleSignOnServices {
				if s.Binding == binding {
					return s.Location
				}
			}
		}
	}
	return ""
}
func (sp *ServiceProvider) Metadata() *EntityDescriptor {
	md := &EntityDescriptor{EntityID: sp.EntityID, SPSSODescriptors: []SPSSODescriptor{{
		ProtocolSupportEnumeration: ProtocolNamespace, WantAssertionsSigned: true,
		AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPPostBinding, Location: sp.AcsURL.String(), Index: 1}},
	}}}
	if state := sp.AssertionEncryption; state != nil {
		md.SPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{{Use: "encryption",
			KeyInfo:           KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(state.certificate.Raw)}}}},
			EncryptionMethods: []EncryptionMethod{{Algorithm: aes256GCM}, {Algorithm: aes128GCM}},
		}}
	}
	return md
}

type AuthnRequest struct {
	XMLName                     xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string       `xml:"ID,attr"`
	Version                     string       `xml:"Version,attr"`
	IssueInstant                time.Time    `xml:"IssueInstant,attr"`
	Destination                 string       `xml:"Destination,attr"`
	AssertionConsumerServiceURL string       `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string       `xml:"ProtocolBinding,attr"`
	Issuer                      Issuer       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                nameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}
type nameIDPolicy struct {
	Format      string `xml:"Format,attr"`
	AllowCreate bool   `xml:"AllowCreate,attr"`
}

func (sp *ServiceProvider) MakeAuthenticationRequest(destination, binding, responseBinding string) (*AuthnRequest, error) {
	u, err := url.Parse(destination)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
		binding != HTTPRedirectBinding || responseBinding != HTTPPostBinding || sp.AllowIDPInitiated {
		return nil, errSAML
	}
	var id [24]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &AuthnRequest{ID: "_" + hex.EncodeToString(id[:]), Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: destination, AssertionConsumerServiceURL: sp.AcsURL.String(), ProtocolBinding: HTTPPostBinding,
		Issuer: Issuer{Value: sp.EntityID}, NameIDPolicy: nameIDPolicy{Format: sp.AuthnNameIDFormat, AllowCreate: true}}, nil
}
func (r *AuthnRequest) Redirect(relay string, sp *ServiceProvider) (*url.URL, error) {
	if len(relay) > 80 || relay == "" {
		return nil, errSAML
	}
	data, err := xml.Marshal(r)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	u, err := url.Parse(r.Destination)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Del("Signature")
	q.Del("SigAlg")
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	q.Set("RelayState", relay)
	u.RawQuery = q.Encode()
	return u, nil
}
func (sp *ServiceProvider) ParseXMLResponse(data []byte, requestIDs []string, acs url.URL) (*Assertion, error) {
	switch sp.encryptionMode() {
	case EncryptionDisabled, EncryptionOptional, EncryptionRequired:
	default:
		return nil, errSAML
	}
	if sp.AllowIDPInitiated || len(requestIDs) != 1 || requestIDs[0] == "" || acs.String() != sp.AcsURL.String() || sp.IDPMetadata == nil {
		return nil, errSAML
	}
	root, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if !named(root, ProtocolNamespace, "Response") {
		return nil, errSAML
	}
	a := allowed(ProtocolNamespace, "Status")
	a[AssertionNamespace+"|Issuer"] = 1
	a[AssertionNamespace+"|Assertion"] = 1
	a[AssertionNamespace+"|EncryptedAssertion"] = 1
	a[dsNamespace+"|Signature"] = 1
	if err := onlyChildren(root, a); err != nil {
		return nil, err
	}
	plain := children(root, AssertionNamespace, "Assertion")
	encrypted := children(root, AssertionNamespace, "EncryptedAssertion")
	if len(plain)+len(encrypted) != 1 ||
		(len(encrypted) == 1 && sp.encryptionMode() == EncryptionDisabled) ||
		(len(plain) == 1 && sp.encryptionMode() == EncryptionRequired) {
		return nil, errSAML
	}
	assertionName := "Assertion"
	expectedSignatures := len(children(root, dsNamespace, "Signature"))
	if len(plain) == 1 {
		expectedSignatures += len(children(plain[0], dsNamespace, "Signature"))
	} else {
		assertionName = "EncryptedAssertion"
	}
	// No hidden assertions or signatures anywhere in extension/key structures.
	if countLocal(root, "Assertion") != len(plain) || countLocal(root, "EncryptedAssertion") != len(encrypted) ||
		countLocal(root, "Signature") != expectedSignatures || expectedSignatures > 2 {
		return nil, errSAML
	}
	original := root
	certs, err := sp.certificates()
	if err != nil || len(certs) == 0 {
		return nil, errSAML
	}
	responseSigned := len(children(root, dsNamespace, "Signature")) == 1
	if responseSigned {
		root, err = verifySignature(root, certs)
		if err != nil {
			return nil, err
		}
	}
	assertion, err := one(root, AssertionNamespace, assertionName)
	if err != nil {
		return nil, errSAML
	}
	if len(encrypted) == 1 {
		// Verify an outer signature over the original ciphertext before decryption.
		// Encryption alone never authenticates the assertion's sender.
		assertion, err = sp.decryptAssertion(assertion)
		if err != nil || countLocal(assertion, "Assertion") != 1 || countLocal(assertion, "EncryptedAssertion") != 0 ||
			countLocal(assertion, "Signature") != len(children(assertion, dsNamespace, "Signature")) ||
			!disjointIDs(original, assertion) {
			return nil, errSAML
		}
	}
	if len(children(assertion, dsNamespace, "Signature")) == 1 {
		assertion, err = verifySignature(assertion, certs)
		if err != nil {
			return nil, err
		}
	} else if !responseSigned {
		return nil, errSAML
	}
	// Even with assertion-only signatures, require response envelope correlation.
	if attribute(root, "ID") == "" || attribute(root, "Version") != "2.0" ||
		attribute(root, "InResponseTo") != requestIDs[0] || attribute(root, "Destination") != acs.String() {
		return nil, errSAML
	}
	issue, err := time.Parse(time.RFC3339Nano, attribute(root, "IssueInstant"))
	if err != nil || issue.After(time.Now().Add(time.Minute*5)) {
		return nil, errSAML
	}
	if issuers := children(root, AssertionNamespace, "Issuer"); len(issuers) > 0 {
		issuer, err := textValue(issuers[0])
		if err != nil || issuer != sp.IDPMetadata.EntityID {
			return nil, errSAML
		}
	}
	status, err := one(root, ProtocolNamespace, "Status")
	if err != nil {
		return nil, err
	}
	if err := onlyChildren(status, allowed(ProtocolNamespace, "StatusCode", "StatusMessage")); err != nil {
		return nil, err
	}
	code, err := one(status, ProtocolNamespace, "StatusCode")
	if err != nil || attribute(code, "Value") != "urn:oasis:names:tc:SAML:2.0:status:Success" || len(code.ChildElements()) != 0 {
		return nil, errSAML
	}
	if err := assertionShape(assertion); err != nil {
		return nil, err
	}
	// Canonicalize the verified subtree to carry its namespace context when only
	// the Response was signed. This performs no further signature transforms.
	canonical, err := canonicalize(assertion, nil, "")
	if err != nil {
		return nil, err
	}
	var result Assertion
	if xml.Unmarshal(canonical, &result) != nil || result.ID == "" || result.Version != "2.0" || result.Issuer.Value != sp.IDPMetadata.EntityID ||
		result.IssueInstant.IsZero() || result.IssueInstant.After(time.Now().Add(time.Minute*5)) {
		return nil, errSAML
	}
	return &result, nil
}
func assertionShape(e *etree.Element) error {
	a := allowed(AssertionNamespace, "Issuer", "Subject", "Conditions")
	a[AssertionNamespace+"|AuthnStatement"] = 0
	a[AssertionNamespace+"|AttributeStatement"] = 0
	if err := onlyChildren(e, a); err != nil {
		return err
	}
	for _, name := range []string{"Issuer", "Subject", "Conditions"} {
		if _, err := one(e, AssertionNamespace, name); err != nil {
			return err
		}
	}
	issuer, _ := one(e, AssertionNamespace, "Issuer")
	if _, err := textValue(issuer); err != nil {
		return err
	}
	subject, _ := one(e, AssertionNamespace, "Subject")
	a = allowed(AssertionNamespace, "NameID")
	a[AssertionNamespace+"|SubjectConfirmation"] = 0
	if err := onlyChildren(subject, a); err != nil {
		return err
	}
	name, err := one(subject, AssertionNamespace, "NameID")
	if err != nil {
		return err
	}
	if _, err := textValue(name); err != nil {
		return err
	}
	for _, c := range children(subject, AssertionNamespace, "SubjectConfirmation") {
		if err := onlyChildren(c, allowed(AssertionNamespace, "SubjectConfirmationData")); err != nil {
			return err
		}
		d, err := one(c, AssertionNamespace, "SubjectConfirmationData")
		if err != nil || len(d.ChildElements()) != 0 {
			return errSAML
		}
	}
	conditions, _ := one(e, AssertionNamespace, "Conditions")
	a = allowed(AssertionNamespace, "OneTimeUse")
	a[AssertionNamespace+"|AudienceRestriction"] = 0
	if err := onlyChildren(conditions, a); err != nil {
		return err
	}
	for _, c := range children(conditions, AssertionNamespace, "AudienceRestriction") {
		if err := onlyChildren(c, allowed(AssertionNamespace, "Audience")); err != nil {
			return err
		}
		audience, err := one(c, AssertionNamespace, "Audience")
		if err != nil {
			return err
		}
		if _, err := textValue(audience); err != nil {
			return err
		}
	}
	for _, s := range children(e, AssertionNamespace, "AuthnStatement") {
		if err := onlyChildren(s, allowed(AssertionNamespace, "SubjectLocality", "AuthnContext")); err != nil {
			return err
		}
	}
	for _, s := range children(e, AssertionNamespace, "AttributeStatement") {
		if err := onlyChildren(s, map[string]int{AssertionNamespace + "|Attribute": 0}); err != nil {
			return err
		}
		for _, attr := range children(s, AssertionNamespace, "Attribute") {
			if err := onlyChildren(attr, map[string]int{AssertionNamespace + "|AttributeValue": 0}); err != nil {
				return err
			}
			for _, v := range children(attr, AssertionNamespace, "AttributeValue") {
				if err := onlyAttributeValue(v); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func onlyAttributeValue(v *etree.Element) error {
	for _, attr := range v.Attr {
		if attr.Space != "" && attr.Key == "nil" {
			return errSAML
		}
	}
	for _, c := range v.ChildElements() {
		if !named(c, AssertionNamespace, "NameID") {
			return errSAML
		}
		if _, err := textValue(c); err != nil {
			return err
		}
	}
	if len(v.ChildElements()) > 1 {
		return errSAML
	}
	return nil
}
