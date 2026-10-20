// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityDecisionRequiresUnambiguousBinding(t *testing.T) {
	const valid = `{"decision_id":"d1","node_id":"node-a","generation":"g1","cid":0,"kid":0,"group_name":"admins-vpn","expires_at":"2026-09-22T10:00:00Z","session_expires_at":"2026-09-22T10:15:00Z"}`
	cases := map[string]string{
		"duplicate-node": strings.Replace(valid, `"node_id":"node-a"`, `"node_id":"node-b","node_id":"node-a"`, 1),
		"escaped-duplicate": strings.Replace(valid, `"cid":0`, `"cid":1,"\u0063id":0`, 1),
		"case-alias": strings.Replace(valid, `"node_id"`, `"NODE_ID"`, 1),
		"null-cid": strings.Replace(valid, `"cid":0`, `"cid":null`, 1),
		"null-document": "null",
	}
	for _, field := range []string{`"decision_id":"d1",`, `"node_id":"node-a",`, `"generation":"g1",`,
		`"cid":0,`, `"kid":0,`, `"expires_at":"2026-09-22T10:00:00Z",`,
		`,"session_expires_at":"2026-09-22T10:15:00Z"`} {
		cases["missing-"+strings.Split(field, ":")[0]] = strings.Replace(valid, field, "", 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			replies := make(chan string, 1)
			replies <- body
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, <-replies)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client().Transport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			decision, err := client.Call(context.Background(), "fetch", Request{})
			if err == nil || Status(err) != 502 || decision != nil {
				t.Fatal("ambiguous or incomplete decision accepted")
			}
			// Explicit zero IDs are real OpenVPN IDs, not missing data.
			replies <- valid
			decision, err = client.Call(context.Background(), "fetch", Request{})
			if err != nil || decision == nil || decision.CID != 0 || decision.KID != 0 || decision.NodeID != "node-a" {
				t.Fatal("explicit zero IDs were refused after malformed response")
			}
		})
	}
}
