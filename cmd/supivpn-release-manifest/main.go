// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// supivpn-release-manifest binds reviewed schema compatibility to local artifacts.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
)

func main() {
	logging.Configure("release_manifest")
	directory := flag.String("artifact-dir", "local/arm64", "directory containing artifacts for one architecture")
	flag.Parse()
	if err := writeManifest(*directory); err != nil {
		logging.Emit(context.Background(), "manifest.failed")
		os.Exit(1)
	}
}

func writeManifest(directory string) error {
	artifacts := map[string]string{}
	for _, name := range []string{"supivpn", "supivpn-controller", "supivpn-profile", "supivpn-migrate", "bootstrap", "bootstrap-agent", "bootstrap-recovery", "supivpn-lambda.zip", "supivpn-agent-lambda.zip", "supivpn-recovery-lambda.zip"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		artifacts[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	data, err := json.MarshalIndent(map[string]any{
		"format": 1, "schema": 11, "schema_digest": postgres.MigrationDigest(),
		"lambda_components":  map[string]any{"public": map[string]any{"artifact": "supivpn-lambda.zip", "required_schema": 11}, "agent": map[string]any{"artifact": "supivpn-agent-lambda.zip", "required_schema": 11}, "recovery": map[string]any{"artifact": "supivpn-recovery-lambda.zip", "required_schema": 11}},
		"compatible_schemas": postgres.CompatibleSchemaDigests(), "artifacts": artifacts,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "release.json.new"), append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(filepath.Join(directory, "release.json.new"), filepath.Join(directory, "release.json"))
}
