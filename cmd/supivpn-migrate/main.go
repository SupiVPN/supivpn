// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// supivpn-migrate is a separate, explicitly invoked deployment operation.
// It is never called from a controller request or from the SupiVPN startup path.
package main

import (
	"context"
	"flag"
	"os"
	"supivpn/internal/postgres"
	"supivpn/internal/logging"
	"time"
)

func main() {
	logging.Configure("migrate")
	configPath := flag.String("config", "", "Non-secret AWS migration configuration JSON; otherwise use SUPIVPN_DATABASE_URL")
	expected := flag.String("expected-schema-sha256", "", "Expected digest of SQL sources from provisioning")
	publicRole := flag.String("public-role", "", "Pre-created restricted public database login")
	agentRole := flag.String("agent-role", "", "Pre-created restricted agent database login")
	recoveryRole := flag.String("recovery-role", "", "Pre-created restricted recovery database login")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx, *configPath, *expected, os.Getenv("SUPIVPN_DATABASE_URL"), postgres.RuntimeRoles{Public: *publicRole, Agent: *agentRole, Recovery: *recoveryRole}); err != nil {
		// Never print raw pgx errors or the supplied DSN.
		logging.Emit(ctx, "database.migration_failed")
		os.Exit(1)
	}
	logging.Emit(ctx, "database.schema_current")
}
