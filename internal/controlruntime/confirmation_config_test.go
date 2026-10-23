// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"supivpn/internal/controller"
	"supivpn/internal/gateway"
	"supivpn/internal/saml"
)

type confirmationConfigBackend struct{ starts int }

func (*confirmationConfigBackend) Ready(context.Context) bool { return true }
func (b *confirmationConfigBackend) Start(context.Context, string, string, [32]byte) error {
	b.starts++
	return nil
}
func (*confirmationConfigBackend) Lookup(context.Context, string, [32]byte) (controller.Pending, error) {
	return controller.Pending{}, controller.ErrLoginExpired
}
func (*confirmationConfigBackend) Complete(context.Context, controller.Pending, controller.Authorization) error {
	return controller.ErrLoginExpired
}

func confirmationConfigJSON(t *testing.T, base Config, value string) string {
	t.Helper()
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(fields, "vpn_login_confirmation")
	} else {
		fields["vpn_login_confirmation"] = json.RawMessage(value)
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestVPNConfirmationConfigurationWiring(t *testing.T) {
	for _, value := range []string{"", "null", "true", "false"} {
		t.Run("value="+value, func(t *testing.T) {
			for _, prefix := range []string{"", "/supivpn"} {
				base := validConfig()
				base.PublicURL += prefix
				configuration, err := ParseConfig(confirmationConfigJSON(t, base, value))
				if err != nil {
					t.Fatal("valid confirmation setting rejected", err)
				}
				if value == "" || value == "null" {
					if configuration.VPNLoginConfirmation != nil {
						t.Fatal("omitted or null setting changed the default")
					}
				} else if configuration.VPNLoginConfirmation == nil || *configuration.VPNLoginConfirmation != (value == "true") {
					t.Fatal("explicit confirmation setting was lost")
				}
				policy, origin, err := configuration.Policy()
				if err != nil {
					t.Fatal(err)
				}
				sp := &saml.ServiceProvider{EntityID: origin.String() + "/saml/metadata",
					AcsURL: *origin.ResolveReference(&url.URL{Path: prefix + "/saml/acs"}),
					IDPMetadata: &saml.EntityDescriptor{EntityID: "https://idp.example.test", IDPSSODescriptors: []saml.IDPSSODescriptor{{
						SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.test/login"}},
					}}}}
				backend := &confirmationConfigBackend{}
				control, err := controller.New(policy, origin, sp, backend, nil)
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				control.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, origin.String()+"/login/test-ticket", nil))
				wantStatus, wantStarts := http.StatusOK, 0
				if value == "false" {
					wantStatus, wantStarts = http.StatusFound, 1
				}
				if response.Code != wantStatus || backend.starts != wantStarts {
					t.Fatal("parsed runtime configuration did not reach the browser handler")
				}
			}
		})
	}
	for _, value := range []string{`"false"`, `"true"`, "0", "1", "[]", "{}"} {
		t.Run("invalid="+value, func(t *testing.T) {
			if _, err := ParseConfig(confirmationConfigJSON(t, validConfig(), value)); err == nil {
				t.Fatal("non-boolean confirmation setting accepted")
			}
		})
	}
}

func TestAgentOnlyRejectsVPNConfirmationSetting(t *testing.T) {
	for _, value := range []string{"", "null", "true", "false"} {
		t.Run("value="+value, func(t *testing.T) {
			base := Config{PublicURL: "https://vpn.example.test", PendingSeconds: 60, Gateway: &gateway.Config{}}
			configuration, err := ParseConfig(confirmationConfigJSON(t, base, value))
			if err != nil {
				t.Fatal(err)
			}
			// An empty DSN fails locally before creating a pool or contacting a DB.
			application, err := OpenAgent(context.Background(), configuration, "", nil)
			if application != nil || err == nil {
				t.Fatal("agent-only validation unexpectedly succeeded")
			}
			want := "database configuration required"
			if value == "true" || value == "false" {
				want = "agent component requires only"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal("confirmation setting was accepted by the wrong component", err)
			}
		})
	}
}
