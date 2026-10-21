// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// MigrationDigest matches the Terraform digest of sorted filename:sha256 lines.
// Comparing the embedded files with checkout files rejects a stale binary.
func MigrationDigest() string {
	return migrationDigest(0)
}

// CompatibleSchemaDigests is deliberately finite. Each new online migration
// requires compatibility tests before extending this list.
func CompatibleSchemaDigests() map[string]string {
	return map[string]string{"7": migrationDigest(7), "8": migrationDigest(8), "9": migrationDigest(9), "10": migrationDigest(10)}
}

func migrationDigest(limit int) string {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		panic("embedded migrations unavailable")
	}
	manifest := ""
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		data, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			panic("embedded migration unavailable")
		}
		manifest += fmt.Sprintf("%s:%x\n", entry.Name(), sha256.Sum256(data))
		count++
		if limit > 0 && count == limit {
			break
		}
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(manifest)))
}
