// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"supivpn/internal/awsruntime"
	"supivpn/internal/logging"
	"supivpn/internal/profile"
)

func run() error {
	initialize := flag.Bool("init", false, "initialize server wrapping key, preserving an existing key")
	openvpn := flag.String("openvpn", "/usr/sbin/openvpn", "absolute path to OpenVPN "+profile.Version)
	server := flag.String("server-key", "/var/lib/supivpn/tls-crypt-v2-server.key", "server wrapping key path")
	secretARN := flag.String("secret-arn", "", "AWS Secrets Manager ARN for the cluster wrapping key")
	flag.Parse()
	if flag.NArg() != 0 || !*initialize {
		return fmt.Errorf("use -init; client profiles require SAML-authorized download")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	issuer := profile.Issuer{OpenVPN: *openvpn}
	if *secretARN != "" {
		store, err := awsruntime.NewSecretsManagerStore(ctx, *secretARN)
		if err != nil {
			return err
		}
		return issuer.EnsureServerKeyInStore(ctx, *server, *secretARN, store)
	}
	return issuer.EnsureServerKey(ctx, *server)
}

func main() {
	logging.Configure("profile")
	if err := run(); err != nil {
		logging.Emit(context.Background(), "profile.issue_failed")
		os.Exit(1)
	}
	logging.Emit(context.Background(), "profile.file_ready")
}
