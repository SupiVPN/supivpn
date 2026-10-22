// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func localControllerConfig() *remoteConfig {
	uid := uint32(os.Geteuid())
	return &remoteConfig{Transport: "unix", AgentSocket: "/run/supivpn-controller/agent.sock", ControllerUID: &uid,
		PublicURL: "https://login.example.test", NodeID: "node-a", StateDirectory: "/var/lib/supivpn-node"}
}

func TestRemoteTransportConfiguration(t *testing.T) {
	if _, _, err := readConfig("../../examples/agent.vm.example.json"); err != nil {
		t.Fatal("local agent example rejected", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*remoteConfig)
		valid  bool
	}{
		{"unix", func(*remoteConfig) {}, true},
		{"explicit-root", func(r *remoteConfig) { uid := uint32(0); r.ControllerUID = &uid }, true},
		{"omitted-uid", func(r *remoteConfig) { r.ControllerUID = nil }, false},
		{"mixed-region", func(r *remoteConfig) { r.Region = "eu-west-1" }, false},
		{"mixed-url", func(r *remoteConfig) { r.AgentURL = "https://agents.example.test" }, false},
		{"relative-socket", func(r *remoteConfig) { r.AgentSocket = "agent.sock" }, false},
		{"noncanonical-socket", func(r *remoteConfig) { r.AgentSocket = "/run/a/../agent.sock" }, false},
		{"missing-socket", func(r *remoteConfig) { r.AgentSocket = "" }, false},
		{"public-http", func(r *remoteConfig) { r.PublicURL = "http://login.example.test" }, false},
		{"state-in-controller-run", func(r *remoteConfig) { r.StateDirectory = "/run/supivpn-controller" }, false},
		{"state-in-agent-run", func(r *remoteConfig) { r.StateDirectory = "/run/supivpn" }, false},
		{"unknown", func(r *remoteConfig) { r.Transport = "auto" }, false},
		{"missing-transport", func(r *remoteConfig) { r.Transport = "" }, false},
		{"aws-with-socket", func(r *remoteConfig) {
			r.Transport = "aws"
			r.AgentURL = "https://agents.example.test"
			r.Region = "eu-west-1"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("../../examples/config.example.json")
			if err != nil {
				t.Fatal(err)
			}
			var c config
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			c.RemoteController = localControllerConfig()
			tc.mutate(c.RemoteController)
			data, err = json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "agent.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readConfig(path); (err == nil) != tc.valid {
				t.Fatalf("unexpected validation: %v", err)
			}
		})
	}
	for _, mode := range []string{"", "aws"} {
		r := &remoteConfig{Transport: mode, AgentURL: "https://agents.example.test", Region: "eu-west-1",
			PublicURL: "https://login.example.test/supivpn", NodeID: "node-a", StateDirectory: "/var/lib/supivpn-node"}
		if err := r.validate(groupConfig()); err != nil {
			t.Fatal("existing AWS configuration rejected", err)
		}
	}
}
