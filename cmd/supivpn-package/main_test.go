// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func packageFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	// Minimal ELF64 header: packaging checks architecture without executing it.
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(header[16:], 2)
	binary.LittleEndian.PutUint16(header[18:], 183)
	binary.LittleEndian.PutUint32(header[20:], 1)
	binary.LittleEndian.PutUint16(header[52:], 64)
	binary.LittleEndian.PutUint16(header[54:], 56)
	binary.LittleEndian.PutUint16(header[58:], 64)
	executable := filepath.Join(dir, "bootstrap")
	if err := os.WriteFile(executable, header, 0700); err != nil {
		t.Fatal(err)
	}
	return dir, executable, filepath.Join("..", "..", "examples", "client.ovpn.example")
}

func readPackage(t *testing.T, path string) map[string][]byte {
	t.Helper()
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	result := make(map[string][]byte)
	for _, f := range z.File {
		if _, exists := result[f.Name]; exists {
			t.Fatalf("duplicate archive member %q", f.Name)
		}
		if f.Name == "bootstrap" && f.Mode().Perm() != 0755 {
			t.Fatal("bootstrap must remain executable")
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		result[f.Name] = data
	}
	return result
}

func TestPackWithExternalMetadata(t *testing.T) {
	dir, executable, template := packageFixture(t)
	output := filepath.Join(dir, "runtime.zip")
	if err := pack(executable, "", template, output, "arm64"); err != nil {
		t.Fatal(err)
	}
	files := readPackage(t, output)
	if len(files) != 2 || len(files["bootstrap"]) == 0 || len(files["client.ovpn.template"]) == 0 {
		t.Fatal("external-metadata package must contain only bootstrap and the profile template")
	}
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := pack(executable, "", template, output, "arm64"); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unchanged inputs must produce an identical artifact")
	}
}

func TestServicePackageContainsOnlyBootstrap(t *testing.T) {
	dir, executable, _ := packageFixture(t)
	output := filepath.Join(dir, "service.zip")
	if err := pack(executable, "", "", output, "arm64"); err != nil {
		t.Fatal(err)
	}
	files := readPackage(t, output)
	if len(files) != 1 || len(files["bootstrap"]) == 0 {
		t.Fatal("service package leaked public component assets")
	}
}

func TestPackWithExplicitMetadata(t *testing.T) {
	dir, executable, template := packageFixture(t)
	metadata := filepath.Join(dir, "idp.xml")
	xml := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>`)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyXML := "<KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>" + base64.StdEncoding.EncodeToString(der) + "</X509Certificate></X509Data></KeyInfo></KeyDescriptor>"
	xml = bytes.Replace(xml, []byte("<SingleSignOnService "), []byte(keyXML+"<SingleSignOnService "), 1)
	if err := os.WriteFile(metadata, xml, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "runtime.zip")
	if err := pack(executable, metadata, template, output, "arm64"); err != nil {
		t.Fatal(err)
	}
	files := readPackage(t, output)
	if len(files) != 3 || !bytes.Equal(files["idp-metadata.xml"], xml) {
		t.Fatal("explicit public metadata must be validated and included")
	}
}

func TestPackRejectsInvalidExplicitMetadata(t *testing.T) {
	for _, data := range []string{"<not-idp/>", strings.Repeat("x", (1<<20)+1)} {
		dir, executable, template := packageFixture(t)
		metadata := filepath.Join(dir, "idp.xml")
		if err := os.WriteFile(metadata, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "runtime.zip")
		if err := pack(executable, metadata, template, output, "arm64"); err == nil {
			t.Fatal("invalid metadata must fail even though bundling is optional")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("invalid input must not create an artifact")
		}
	}
}

func TestPackArchitecture(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, machine := range []uint16{183, 62, 3} {
			t.Run(fmt.Sprintf("%s/%d", arch, machine), func(t *testing.T) {
				dir, executable, template := packageFixture(t)
				header, err := os.ReadFile(executable)
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint16(header[18:], machine)
				if err := os.WriteFile(executable, header, 0700); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(dir, "lambda.zip")
				err = pack(executable, "", template, output, arch)
				want := (arch == "arm64" && machine == 183) || (arch == "amd64" && machine == 62)
				if (err == nil) != want {
					t.Fatalf("architecture validation: %v", err)
				}
				if !want {
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("rejected artifact written")
					}
				}
			})
		}
	}
}
