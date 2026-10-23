// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package saml implements SupiVPN's SP-initiated Redirect/POST Web SSO subset.
// Only the algorithms listed in SECURITY.md are accepted.
package saml

import (
	"encoding/xml"
	"github.com/beevik/etree"
	"time"
)

const (
	AssertionNamespace      = "urn:oasis:names:tc:SAML:2.0:assertion"
	ProtocolNamespace       = "urn:oasis:names:tc:SAML:2.0:protocol"
	MetadataNamespace       = "urn:oasis:names:tc:SAML:2.0:metadata"
	HTTPRedirectBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPostBinding         = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	UnspecifiedNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

type Issuer struct {
	Value string `xml:",chardata"`
}
type NameID struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}
type Subject struct {
	NameID               *NameID               `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmations []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}
type SubjectConfirmation struct {
	Method                  string                   `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}
type SubjectConfirmationData struct {
	InResponseTo string    `xml:"InResponseTo,attr"`
	Recipient    string    `xml:"Recipient,attr"`
	NotBefore    time.Time `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
}
type Audience struct {
	Value string `xml:",chardata"`
}
type AudienceRestriction struct {
	Audience Audience `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}
type Conditions struct {
	NotBefore            time.Time             `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter         time.Time             `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}
type AuthnStatement struct {
	AuthnInstant        time.Time  `xml:"AuthnInstant,attr"`
	SessionIndex        string     `xml:"SessionIndex,attr,omitempty"`
	SessionNotOnOrAfter *time.Time `xml:"SessionNotOnOrAfter,attr,omitempty"`
}
type AttributeValue struct {
	Type   string  `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr,omitempty"`
	Value  string  `xml:",chardata"`
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID,omitempty"`
}
type Attribute struct {
	Name         string           `xml:"Name,attr"`
	NameFormat   string           `xml:"NameFormat,attr,omitempty"`
	FriendlyName string           `xml:"FriendlyName,attr,omitempty"`
	Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}
type Assertion struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                  string               `xml:"ID,attr"`
	Version             string               `xml:"Version,attr"`
	IssueInstant        time.Time            `xml:"IssueInstant,attr"`
	Issuer              Issuer               `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject             *Subject             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions          *Conditions          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatements     []AuthnStatement     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatements []AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}
type StatusCode struct {
	Value string `xml:"Value,attr"`
}
type Status struct {
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}
type Response struct {
	XMLName      xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string     `xml:"ID,attr"`
	InResponseTo string     `xml:"InResponseTo,attr"`
	Version      string     `xml:"Version,attr"`
	IssueInstant time.Time  `xml:"IssueInstant,attr"`
	Destination  string     `xml:"Destination,attr"`
	Issuer       *Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// Element is also used by the synthetic IdP in integration tests.
func (r Response) Element() *etree.Element {
	data, err := xml.Marshal(r)
	if err != nil {
		panic(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		panic(err)
	}
	doc.Root().CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	return doc.Root()
}

type Endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}
type IndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}
type X509Certificate struct {
	Data string `xml:",chardata"`
}
type X509Data struct {
	X509Certificates []X509Certificate `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}
type KeyInfo struct {
	X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}
type KeyDescriptor struct {
	Use               string             `xml:"use,attr,omitempty"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"urn:oasis:names:tc:SAML:2.0:metadata EncryptionMethod,omitempty"`
}
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}
type IDPSSODescriptor struct {
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []KeyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SingleSignOnServices       []Endpoint      `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
}
type SPSSODescriptor struct {
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        bool              `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool              `xml:"WantAssertionsSigned,attr"`
	KeyDescriptors             []KeyDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor,omitempty"`
	AssertionConsumerServices  []IndexedEndpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
}
type EntityDescriptor struct {
	XMLName           xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID          string             `xml:"entityID,attr"`
	ValidUntil        *time.Time         `xml:"validUntil,attr,omitempty"`
	IDPSSODescriptors []IDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	SPSSODescriptors  []SPSSODescriptor  `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}
