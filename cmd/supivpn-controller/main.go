// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"supivpn/internal/controlruntime"
	"supivpn/internal/vm"
	"supivpn/internal/logging"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logging.Configure("controller")
	path := flag.String("config", "/etc/supivpn/controller.json", "controller configuration")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *path); err != nil {
		logging.Emit(ctx, "component.stopped")
		os.Exit(1)
	}
}
func run(ctx context.Context, path string) error {
	c, err := controlruntime.ReadConfig(path)
	if err != nil {
		return err
	}
	if c.VM == nil {
		return fmt.Errorf("VM configuration required")
	}
	if err = c.VM.Validate(); err != nil {
		return err
	}
    closeLogs, err := logging.Setup("controller", c.Logging)
    if err != nil { return err }
    defer closeLogs()
	app, err := controlruntime.Open(ctx, c, os.Getenv("SUPIVPN_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer app.Close()
	return vm.Serve(ctx, *c.VM, app.Public, app.Agents)
}
