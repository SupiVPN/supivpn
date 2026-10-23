// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// EncryptionConfig contains file references only, never key material.
type EncryptionConfig struct {
	Mode            string `json:"mode"`
	CertificateFile string `json:"certificate_file,omitempty"`
	PrivateKeyFile  string `json:"private_key_file,omitempty"`
}

func (c *EncryptionConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.Mode {
	case "", EncryptionDisabled:
		if c.CertificateFile != "" || c.PrivateKeyFile != "" {
			return errors.New("disabled assertion encryption must not configure key files")
		}
	case EncryptionOptional, EncryptionRequired:
		if !filepath.IsAbs(c.CertificateFile) || !filepath.IsAbs(c.PrivateKeyFile) || c.CertificateFile == c.PrivateKeyFile {
			return errors.New("assertion encryption requires separate absolute certificate_file and private_key_file paths")
		}
	default:
		return errors.New("assertion encryption mode must be disabled, optional or required")
	}
	return nil
}

func (c *EncryptionConfig) Load() (*AssertionEncryption, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c == nil || c.Mode == "" || c.Mode == EncryptionDisabled {
		return nil, nil
	}
	// These are operator-provisioned files. Never log paths, PEM or parse errors.
	keyPEM, err := encryptionPEMFile(c.PrivateKeyFile, true)
	if err != nil {
		return nil, errors.New("cannot load SAML encryption private key")
	}
	defer clear(keyPEM)
	block, rest := pem.Decode(keyPEM)
	if !singleEncryptionPEM(keyPEM, block, rest) {
		return nil, errSAML
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, errSAML
	}
	if err != nil || key == nil {
		return nil, errSAML
	}
	certPEM, err := encryptionPEMFile(c.CertificateFile, false)
	if err != nil {
		return nil, errors.New("cannot load SAML encryption certificate")
	}
	certBlock, rest := pem.Decode(certPEM)
	if !singleEncryptionPEM(certPEM, certBlock, rest) || certBlock.Type != "CERTIFICATE" {
		return nil, errSAML
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errSAML
	}
	return NewAssertionEncryption(c.Mode, key, cert)
}

func singleEncryptionPEM(data []byte, block *pem.Block, rest []byte) bool {
	// pem.Decode deliberately skips malformed leading blocks. A file starting
	// with the expected marker could otherwise hide another object before the
	// decoded one. Base64 cannot contain these boundary markers.
	return block != nil && len(block.Headers) == 0 && len(bytes.TrimSpace(rest)) == 0 &&
		bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN "+block.Type+"-----")) &&
		bytes.Count(data, []byte("-----BEGIN ")) == 1 && bytes.Count(data, []byte("-----END ")) == 1
}

func encryptionPEMFile(path string, private bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errSAML
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 || st.Mode().Perm()&0022 != 0 ||
		(private && st.Mode().Perm()&0137 != 0) {
		return nil, errSAML
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		clear(data)
		return nil, errSAML
	}
	return data, nil
}
