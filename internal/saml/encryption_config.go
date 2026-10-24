// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// EncryptionConfig contains deployment references only, never key material.
type EncryptionConfig struct {
	Mode                string `json:"mode"`
	CertificateFile     string `json:"certificate_file,omitempty"`
	PrivateKeyFile      string `json:"private_key_file,omitempty"`
	PrivateKeySecretARN string `json:"private_key_secret_arn,omitempty"`
}

// EncryptionKeyLoader is supplied by a deployment adapter. It returns a
// caller-owned PEM buffer, which LoadWithKey clears even on failure.
type EncryptionKeyLoader func(context.Context, string) ([]byte, error)

func (c *EncryptionConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.Mode {
	case "", EncryptionDisabled:
		if c.CertificateFile != "" || c.PrivateKeyFile != "" || c.PrivateKeySecretARN != "" {
			return errors.New("disabled assertion encryption must not configure keys")
		}
	case EncryptionOptional, EncryptionRequired:
		if !filepath.IsAbs(c.CertificateFile) || (c.PrivateKeyFile == "") == (c.PrivateKeySecretARN == "") ||
			(c.PrivateKeyFile != "" && (!filepath.IsAbs(c.PrivateKeyFile) || c.CertificateFile == c.PrivateKeyFile)) {
			return errors.New("assertion encryption requires an absolute certificate_file and exactly one private_key_file or private_key_secret_arn")
		}
	default:
		return errors.New("assertion encryption mode must be disabled, optional or required")
	}
	return nil
}

func (c *EncryptionConfig) Load() (*AssertionEncryption, error) {
	return c.LoadWithKey(context.Background(), nil)
}

// LoadWithKey loads once at initialization. A secret reference requires an
// explicit adapter; it never falls back to a file or weaker encryption mode.
func (c *EncryptionConfig) LoadWithKey(ctx context.Context, loader EncryptionKeyLoader) (*AssertionEncryption, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c == nil || c.Mode == "" || c.Mode == EncryptionDisabled {
		return nil, nil
	}
	// Never log paths, secret references, PEM or provider/parse errors.
	var keyPEM []byte
	var err error
	if c.PrivateKeySecretARN != "" {
		if loader == nil || ctx.Err() != nil {
			return nil, errors.New("SAML encryption secret loader unavailable")
		}
		keyPEM, err = loader(ctx, c.PrivateKeySecretARN)
	} else {
		keyPEM, err = encryptionPEMFile(c.PrivateKeyFile, true)
	}
	defer clear(keyPEM)
	if err != nil || ctx.Err() != nil || len(keyPEM) == 0 || len(keyPEM) > 64<<10 {
		return nil, errors.New("cannot load SAML encryption private key")
	}
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
