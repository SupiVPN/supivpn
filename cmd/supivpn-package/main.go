// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// supivpn-package packages the executable, profile template and optional public IdP metadata.
package main

import (
	"archive/zip"
	"context"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"os"
	"supivpn/internal/saml"
	"time"

	"supivpn/internal/profile"
	"supivpn/internal/logging"
)

func main() {
	logging.Configure("package")
	arch := flag.String("arch", "arm64", "expected Linux architecture: arm64 or amd64")
	binary := flag.String("binary", "local/arm64/bootstrap", "Linux bootstrap")
	metadata := flag.String("metadata", "", "optional public IdP metadata file; omit when deployment supplies a layer")
	template := flag.String("template", "examples/client.ovpn.example", "public profile template without a client key")
	service := flag.Bool("service-only", false, "package only the agent/recovery bootstrap; no SAML/profile assets")
	output := flag.String("output", "local/arm64/supivpn-lambda.zip", "Lambda artifact")
	flag.Parse()
	if *service {
		*template = ""
		if *metadata != "" {
			logging.Emit(context.Background(), "configuration.refused")
			os.Exit(1)
		}
	}
	if err := pack(*binary, *metadata, *template, *output, *arch); err != nil {
		logging.Emit(context.Background(), "package.failed")
		os.Exit(1)
	}
}
func pack(binary, metadata, template, output, arch string) error {
	machine, ok := map[string]elf.Machine{"arm64": elf.EM_AARCH64, "amd64": elf.EM_X86_64}[arch]
	if !ok {
		return fmt.Errorf("unsupported architecture")
	}
	executable, err := elf.Open(binary)
	if err != nil {
		return fmt.Errorf("bootstrap must be ELF")
	}
	if executable.Class != elf.ELFCLASS64 || executable.Data != elf.ELFDATA2LSB || executable.Machine != machine {
		executable.Close()
		return fmt.Errorf("bootstrap architecture does not match requested target")
	}
	executable.Close()
	var data []byte
	if metadata != "" {
		f, openErr := os.Open(metadata)
		if openErr != nil {
			return fmt.Errorf("metadata unavailable")
		}
		data, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		f.Close()
		if err != nil || len(data) > 1<<20 {
			return fmt.Errorf("metadata too large")
		}
		md, parseErr := saml.ParseMetadata(data)
		if parseErr != nil || len(md.IDPSSODescriptors) == 0 {
			return fmt.Errorf("invalid public IdP metadata")
		}
	}
	var templateData []byte
	if template != "" {
		tf, err := os.Open(template)
		if err != nil {
			return fmt.Errorf("profile template unavailable")
		}
		templateData, err = io.ReadAll(io.LimitReader(tf, (64<<10)+1))
		tf.Close()
		if err != nil {
			return fmt.Errorf("profile template unavailable")
		}
		if _, err = profile.DownloadIssuer(templateData, "supivpn.example.test", func(context.Context) ([]byte, error) { return nil, nil }); err != nil {
			return fmt.Errorf("profile template must contain the unfilled client-key placeholder")
		}
	}
	if output == binary || output == metadata || output == template {
		return fmt.Errorf("output must differ from input")
	}
	dest, err := os.Create(output)
	if err != nil {
		return err
	}
	defer dest.Close()
	z := zip.NewWriter(dest)
	for _, file := range []struct {
		name, path string
		mode       os.FileMode
	}{
		{"bootstrap", binary, 0755}, {"idp-metadata.xml", metadata, 0644}, {"client.ovpn.template", template, 0644},
	} {
		if file.path == "" {
			continue
		}
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		header.SetMode(file.mode)
		w, err := z.CreateHeader(header)
		if err != nil {
			return err
		}
		if file.name == "idp-metadata.xml" {
			_, err = w.Write(data)
		} else if file.name == "client.ovpn.template" {
			_, err = w.Write(templateData)
		} else {
			f, openErr := os.Open(file.path)
			if openErr != nil {
				return openErr
			}
			_, err = io.Copy(w, f)
			f.Close()
		}
		if err != nil {
			return err
		}
	}
	if err = z.Close(); err != nil {
		return err
	}
	return dest.Close()
}
