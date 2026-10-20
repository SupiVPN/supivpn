// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"supivpn/internal/saml"
)

// Opt-in deployment check: reads only the explicitly supplied public metadata.
// Ordinary unit tests remain independent of local files and a live IdP.
func TestLocalIDPMetadata(t *testing.T) {
	path := os.Getenv("SUPIVPN_TEST_IDP_METADATA")
	if path == "" {
		t.Skip("set SUPIVPN_TEST_IDP_METADATA to check exported public IdP metadata")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read the supplied IdP metadata file")
	}
	if len(data) == 0 || len(data) > 1<<20 {
		t.Fatal("IdP metadata must contain 1 byte through 1 MiB")
	}
	md, err := saml.ParseMetadata(data)
	if err != nil || md.EntityID == "" || len(md.IDPSSODescriptors) == 0 {
		t.Fatal("supplied file is not usable IdP metadata")
	}
	sp := &saml.ServiceProvider{IDPMetadata: md}
	u, err := url.Parse(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		t.Fatal("IdP metadata must offer HTTPS HTTP-Redirect SSO")
	}
	validSigningCertificate := false
	for _, descriptor := range md.IDPSSODescriptors {
		for _, key := range descriptor.KeyDescriptors {
			if key.Use != "" && key.Use != "signing" {
				continue
			}
			for _, encoded := range key.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded.Data), ""))
				if err != nil {
					t.Fatal("invalid signing certificate encoding in IdP metadata")
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal("invalid signing certificate in IdP metadata")
				}
				now := time.Now()
				if !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) {
					validSigningCertificate = true
				}
			}
		}
	}
	if !validSigningCertificate {
		t.Fatal("IdP metadata has no currently valid signing certificate")
	}
	t.Log("IdP metadata parsed; HTTPS Redirect SSO and a valid signing certificate are available")
}
