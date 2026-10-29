// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"supivpn/internal/controlruntime"
	"supivpn/internal/logging"
	"supivpn/internal/metrics"
	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
	"supivpn/internal/vm"
	"syscall"
	"time"
)

func main() {
	logging.Configure("controller")
	path := flag.String("config", "/etc/supivpn/controller.json", "controller configuration")
	operator := flag.Bool("operator-request", false, "send an operator request from stdin using the configured database")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	if *operator {
		err = operate(ctx, *path)
	} else {
		err = run(ctx, *path)
	}
	if err != nil {
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
	if err != nil {
		return err
	}
	defer closeLogs()
	app, err := controlruntime.Open(ctx, c, os.Getenv("SUPIVPN_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer app.Close()
	stopMetrics, err := metrics.Listen(ctx, c.Metrics, app.Metrics)
	if err != nil {
		return err
	}
	defer stopMetrics()
	return vm.Serve(ctx, *c.VM, app.Public, app.Agents)
}

func operate(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := controlruntime.ReadConfig(path)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(raw) > 8192 {
		return errors.New("invalid operator request")
	}
	q, err := operatorapi.Decode(raw)
	if err != nil || q.ProfileID == "" && q.Action != "profile-list" {
		return errors.New("only profile operations are available through this VM command")
	}
	pool, err := postgres.OpenWithTLS(ctx, os.Getenv("SUPIVPN_DATABASE_URL"), nil, c.DatabaseTLS)
	if err != nil {
		return err
	}
	defer pool.Close()
	store := postgres.New(pool)
	var reply any
	if q.Action == "profile-list" {
		state, listErr := store.ListProfiles(ctx, q)
		if listErr != nil {
			reply = operatorapi.Reply{Error: "unavailable"}
		} else {
			reply = operatorapi.Reply{OK: true, State: &state}
		}
	} else {
		reply, err = operatorapi.Handler(store)(ctx, raw)
	}
	if err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(reply); err != nil {
		return errors.New("cannot write operator response")
	}
	if r, ok := reply.(operatorapi.Reply); !ok || !r.OK {
		return errors.New("operator request refused")
	}
	return nil
}
