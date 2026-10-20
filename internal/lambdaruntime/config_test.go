// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package lambdaruntime

import "testing"

func TestHTTPRejectsLegacyPowerCapabilitiesBeforeConnecting(t *testing.T) {
	for _, key := range []string{"SUPIVPN_EC2_FENCING", "SUPIVPN_EC2_RECOVERY", "SUPIVPN_PRUNE_RULE_ARN", "SUPIVPN_OPERATOR_CONTROL"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "1")
			for _, public := range []bool{true, false} {
				if err := runHTTP(public); err == nil || err.Error() != "move recovery settings to the recovery function" {
					t.Fatal("stale power configuration was not refused before initialization")
				}
			}
		})
	}
}

func TestRecoveryConfigurationDoesNotAcceptHTTPConfiguration(t *testing.T) {
	for _, raw := range []string{`{"public_url":"https://example.test"}`, `{"node_ids":[]} {}`, `{"database_tls":{"mode":"disable"}}`,
        `{"logging":{"output":"file"}}`, `{"logging":{"output":"stderr","retention_days":7}}`,
        `{"logging":{"unknown":true}}`} {
		if _, err := parseRecovery(raw); err == nil {
			t.Fatal("invalid recovery configuration accepted")
		}
	}
	c, err := parseRecovery(`{"node_ids":["i-0123456789abcdef0"],"automatic_recovery":true,"database_tls":{"mode":"require"}}`)
	if err != nil || !c.AutomaticRecovery || len(c.NodeIDs) != 1 {
		t.Fatal("valid recovery configuration refused")
	}
	t.Setenv("SUPIVPN_CONTROLLER_JSON", `{}`)
	if err := runRecovery(); err == nil || err.Error() != "recovery must not receive public controller configuration" {
		t.Fatal("shared configuration accepted")
	}
}
