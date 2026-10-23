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
	_ "crypto/sha1" // XML Encryption OAEP defaults; never an XML signature digest.
	"crypto/x509"
	"strings"
	"time"

	"github.com/beevik/etree"
)

const (
	EncryptionDisabled = "disabled"
	EncryptionOptional = "optional"
	EncryptionRequired = "required"
	xencNamespace      = "http://www.w3.org/2001/04/xmlenc#"
	xenc11Namespace    = "http://www.w3.org/2009/xmlenc11#"
	aes128GCM          = xenc11Namespace + "aes128-gcm"
	aes256GCM          = xenc11Namespace + "aes256-gcm"
	rsaOAEP            = xenc11Namespace + "rsa-oaep"
	rsaOAEP10          = xencNamespace + "rsa-oaep-mgf1p"
)

// AssertionEncryption owns a dedicated decryption key, separate from TLS and
// IdP signature verification. Construct it once before serving requests.
type AssertionEncryption struct {
	mode        string
	key         *rsa.PrivateKey
	certificate *x509.Certificate
}

func NewAssertionEncryption(mode string, key *rsa.PrivateKey, certificate *x509.Certificate) (*AssertionEncryption, error) {
	if mode == "" {
		mode = EncryptionDisabled
	}
	if mode == EncryptionDisabled {
		if key != nil || certificate != nil {
			return nil, errSAML
		}
		return nil, nil
	}
	if mode != EncryptionOptional && mode != EncryptionRequired {
		return nil, errSAML
	}
	if key == nil || key.N == nil || certificate == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
		return nil, errSAML
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !key.PublicKey.Equal(public) || !encryptionCertificateValid(certificate) {
		return nil, errSAML
	}
	key.Precompute()
	return &AssertionEncryption{mode: mode, key: key, certificate: certificate}, nil
}

func countLocal(root *etree.Element, name string) int {
	count := 0
	if root.Tag == name {
		count++
	}
	for _, child := range root.ChildElements() {
		count += countLocal(child, name)
	}
	return count
}

// Each document has already passed parseXML's duplicate-ID check. Keep that
// invariant across the encryption boundary, including IDs on signature nodes.
func disjointIDs(outer, inner *etree.Element) bool {
	ids := make(map[string]bool)
	var walk func(*etree.Element, bool) bool
	walk = func(e *etree.Element, check bool) bool {
		for _, attr := range e.Attr {
			if strings.EqualFold(attr.Key, "id") && attr.Space != "xmlns" {
				if check && ids[attr.Value] {
					return false
				}
				if !check {
					ids[attr.Value] = true
				}
			}
		}
		for _, child := range e.ChildElements() {
			if !walk(child, check) {
				return false
			}
		}
		return true
	}
	walk(outer, false)
	return walk(inner, true)
}
func encryptionCertificateValid(cert *x509.Certificate) bool {
	now := time.Now()
	return cert != nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) &&
		(cert.KeyUsage == 0 || cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0)
}
func (sp *ServiceProvider) encryptionMode() string {
	if sp.AssertionEncryption == nil {
		return EncryptionDisabled
	}
	return sp.AssertionEncryption.mode
}

// XML Encryption 1.1: a 96-bit nonce followed by ciphertext and a 128-bit GCM
// tag. No CBC, RSA v1.5, remote references, key discovery or algorithm fallback.
func (sp *ServiceProvider) decryptAssertion(wrapper *etree.Element) (*etree.Element, error) {
	state := sp.AssertionEncryption
	if state == nil || (state.mode != EncryptionOptional && state.mode != EncryptionRequired) ||
		!encryptionCertificateValid(state.certificate) {
		return nil, errSAML
	}
	if !named(wrapper, AssertionNamespace, "EncryptedAssertion") ||
		onlyChildren(wrapper, allowed(xencNamespace, "EncryptedData")) != nil {
		return nil, errSAML
	}
	data, err := one(wrapper, xencNamespace, "EncryptedData")
	if err != nil || attribute(data, "Type") != xencNamespace+"Element" {
		return nil, errSAML
	}
	if onlyChildren(data, map[string]int{xencNamespace + "|EncryptionMethod": 1, dsNamespace + "|KeyInfo": 1, xencNamespace + "|CipherData": 1}) != nil {
		return nil, errSAML
	}
	method, err := one(data, xencNamespace, "EncryptionMethod")
	if err != nil || onlyChildren(method, allowed(xencNamespace, "KeySize")) != nil {
		return nil, errSAML
	}
	size := 0
	switch attribute(method, "Algorithm") {
	case aes128GCM:
		size = 16
	case aes256GCM:
		size = 32
	default:
		return nil, errSAML
	}
	if values := children(method, xencNamespace, "KeySize"); len(values) > 0 {
		text, e := textValue(values[0])
		if e != nil || (size == 16 && text != "128") || (size == 32 && text != "256") {
			return nil, errSAML
		}
	}
	info, err := one(data, dsNamespace, "KeyInfo")
	if err != nil || onlyChildren(info, allowed(xencNamespace, "EncryptedKey")) != nil {
		return nil, errSAML
	}
	encryptedKey, err := one(info, xencNamespace, "EncryptedKey")
	if err != nil || (attribute(encryptedKey, "Recipient") != "" && attribute(encryptedKey, "Recipient") != sp.EntityID) {
		return nil, errSAML
	}
	if onlyChildren(encryptedKey, map[string]int{xencNamespace + "|EncryptionMethod": 1, xencNamespace + "|CipherData": 1,
		dsNamespace + "|KeyInfo": 1, xencNamespace + "|ReferenceList": 1}) != nil {
		return nil, errSAML
	}
	// Embedded certificate/name is descriptive only. Never use it as a key source.
	if hints := children(encryptedKey, dsNamespace, "KeyInfo"); len(hints) > 0 {
		if onlyChildren(hints[0], allowed(dsNamespace, "KeyName", "X509Data")) != nil {
			return nil, errSAML
		}
		for _, name := range children(hints[0], dsNamespace, "KeyName") {
			if _, e := textValue(name); e != nil {
				return nil, errSAML
			}
		}
		for _, certs := range children(hints[0], dsNamespace, "X509Data") {
			if onlyChildren(certs, allowed(dsNamespace, "X509Certificate")) != nil {
				return nil, errSAML
			}
			cert, e := one(certs, dsNamespace, "X509Certificate")
			if e != nil {
				return nil, errSAML
			}
			if _, e = textValue(cert); e != nil {
				return nil, errSAML
			}
		}
	}
	if refs := children(encryptedKey, xencNamespace, "ReferenceList"); len(refs) > 0 {
		if onlyChildren(refs[0], allowed(xencNamespace, "DataReference")) != nil {
			return nil, errSAML
		}
		ref, e := one(refs[0], xencNamespace, "DataReference")
		if e != nil || len(ref.ChildElements()) != 0 || attribute(data, "Id") == "" || attribute(ref, "URI") != "#"+attribute(data, "Id") {
			return nil, errSAML
		}
	}
	keyMethod, err := one(encryptedKey, xencNamespace, "EncryptionMethod")
	if err != nil {
		return nil, errSAML
	}
	options, err := oaepOptions(keyMethod)
	if err != nil {
		return nil, errSAML
	}
	wrapped, err := cipherValue(encryptedKey)
	if err != nil || len(wrapped) != state.key.Size() {
		return nil, errSAML
	}
	encrypted, err := cipherValue(data)
	if err != nil || len(encrypted) <= 12+16 || len(encrypted) > maxXMLBytes {
		return nil, errSAML
	}
	key, err := state.key.Decrypt(rand.Reader, wrapped, options)
	if err != nil {
		return nil, errSAML
	}
	defer clear(key)
	if len(key) != size {
		return nil, errSAML
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errSAML
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errSAML
	}
	plaintext, err := aead.Open(nil, encrypted[:12], encrypted[12:], nil)
	if err != nil {
		return nil, errSAML
	}
	defer clear(plaintext)
	assertion, err := parseXML(plaintext)
	if err != nil || !named(assertion, AssertionNamespace, "Assertion") {
		return nil, errSAML
	}
	return assertion, nil
}
func cipherValue(e *etree.Element) ([]byte, error) {
	data, err := one(e, xencNamespace, "CipherData")
	if err != nil || onlyChildren(data, allowed(xencNamespace, "CipherValue")) != nil {
		return nil, errSAML
	}
	value, err := one(data, xencNamespace, "CipherValue")
	if err != nil {
		return nil, errSAML
	}
	text, err := textValue(value)
	if err != nil {
		return nil, errSAML
	}
	return decode64(text)
}
func oaepOptions(method *etree.Element) (*rsa.OAEPOptions, error) {
	algorithm := attribute(method, "Algorithm")
	if algorithm != rsaOAEP && algorithm != rsaOAEP10 {
		return nil, errSAML
	}
	if onlyChildren(method, map[string]int{dsNamespace + "|DigestMethod": 1, xenc11Namespace + "|MGF": 1, xencNamespace + "|OAEPparams": 1}) != nil {
		return nil, errSAML
	}
	options := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	if values := children(method, dsNamespace, "DigestMethod"); len(values) > 0 {
		if len(values[0].ChildElements()) != 0 {
			return nil, errSAML
		}
		switch attribute(values[0], "Algorithm") {
		case dsNamespace + "sha1":
			options.Hash = crypto.SHA1
		case digestSHA256:
			options.Hash = crypto.SHA256
		default:
			return nil, errSAML
		}
	}
	if values := children(method, xenc11Namespace, "MGF"); len(values) > 0 {
		if algorithm == rsaOAEP10 || len(values[0].ChildElements()) != 0 {
			return nil, errSAML
		}
		switch attribute(values[0], "Algorithm") {
		case xenc11Namespace + "mgf1sha1":
			options.MGFHash = crypto.SHA1
		case xenc11Namespace + "mgf1sha256":
			options.MGFHash = crypto.SHA256
		default:
			return nil, errSAML
		}
	}
	if values := children(method, xencNamespace, "OAEPparams"); len(values) > 0 {
		text, err := textValue(values[0])
		if err != nil {
			return nil, errSAML
		}
		if text != "" {
			options.Label, err = decode64(text)
			if err != nil || len(options.Label) > 64 {
				return nil, errSAML
			}
		}
	}
	return options, nil
}
