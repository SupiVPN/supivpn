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
	"supivpn/internal/profile"
	"supivpn/internal/logging"
)

func run() error {
	initialize := flag.Bool("init", false, "initialize server wrapping key, preserving an existing key")
	openvpn := flag.String("openvpn", "/usr/sbin/openvpn", "absolute path to OpenVPN "+profile.Version)
	server := flag.String("server-key", "/var/lib/supivpn/tls-crypt-v2-server.key", "server wrapping key path")
	secretARN := flag.String("secret-arn", "", "AWS Secrets Manager ARN for the cluster wrapping key")
	template := flag.String("template", "/etc/supivpn/client.ovpn.template", "client profile template")
	output := flag.String("out", "", "new client profile file (0600); never stdout")
	flag.Parse()
	if flag.NArg() != 0 || (*initialize == (*output != "")) {
		return fmt.Errorf("use either -init or -out FILE")
	}
	if *secretARN != "" && !*initialize {
		return fmt.Errorf("-secret-arn is only valid with -init")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	issuer := profile.Issuer{OpenVPN: *openvpn}
	if *initialize {
		if *secretARN != "" {
			store, err := awsruntime.NewSecretsManagerStore(ctx, *secretARN)
			if err != nil {
				return err
			}
			return issuer.EnsureServerKeyInStore(ctx, *server, *secretARN, store)
		}
		return issuer.EnsureServerKey(ctx, *server)
	}
	data, err := os.ReadFile(*template)
	if err != nil {
		return err
	}
	return issuer.Issue(ctx, *server, data, *output)
}

func main() {
	logging.Configure("profile")
	if err := run(); err != nil {
		logging.Emit(context.Background(), "profile.issue_failed")
		os.Exit(1)
	}
	logging.Emit(context.Background(), "profile.file_ready")
}
