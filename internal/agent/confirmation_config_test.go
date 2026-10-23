// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/controller"
	"supivpn/internal/saml"
)

func confirmationConfigFile(t *testing.T, value string, remote bool) string {
	t.Helper()
	configuration := config{PublicURL: "https://vpn.example.test:8443", Listen: ":8443",
		TLSCertificate: "/test/tls.crt", TLSChain: "/test/chain.crt", TLSPrivateKey: "/test/tls.key",
		IDPMetadata: "/test/metadata.xml", ManagementSocket: "/run/supivpn/management.sock",
		AllowedSubjects: []string{"test-user"}, PendingSeconds: 180, SessionSeconds: 900}
	if remote {
		groups := groupConfig()
		configuration.AllowedSubjects = nil
		configuration.SAMLGroupsAttribute = groups.SAMLGroupsAttribute
		configuration.VPNNetwork = groups.VPNNetwork
		configuration.GroupPools = groups.GroupPools
		configuration.RemoteController = localControllerConfig()
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if value != "" {
		fields["vpn_login_confirmation"] = json.RawMessage(value)
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVPNConfirmationConfigurationWiring(t *testing.T) {
	_, metadata := testIdP(t)
	for _, value := range []string{"", "null", "true", "false"} {
		t.Run("value="+value, func(t *testing.T) {
			configuration, _, err := readConfig(confirmationConfigFile(t, value, false))
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
			app, commands := testApp(t, metadata)
			app.config = configuration
			pending := app.tickets["test-ticket"]
			pending.requestID, pending.browserHash = "", [32]byte{}
			control, err := newController(app.agent, app.sp)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			control.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, app.origin.String()+"/login/test-ticket", nil))
			want := http.StatusOK
			if value == "false" {
				want = http.StatusFound
			}
			if response.Code != want || (pending.requestID != "") != (value == "false") {
				t.Fatal("parsed agent configuration did not reach the browser handler")
			}
			select {
			case <-commands:
				t.Fatal("login navigation authorized a VPN connection")
			default:
			}
		})
	}
	for _, value := range []string{`"false"`, `"true"`, "0", "1", "[]", "{}"} {
		t.Run("invalid="+value, func(t *testing.T) {
			if _, _, err := readConfig(confirmationConfigFile(t, value, false)); err == nil {
				t.Fatal("non-boolean confirmation setting accepted")
			}
		})
	}
}

func TestRemoteNodeRejectsVPNConfirmationSetting(t *testing.T) {
	for _, value := range []string{"", "null", "true", "false"} {
		t.Run("value="+value, func(t *testing.T) {
			_, _, err := readConfig(confirmationConfigFile(t, value, true))
			if value == "true" || value == "false" {
				if err == nil || !strings.Contains(err.Error(), "confirmation belongs to the remote controller") {
					t.Fatal("remote node accepted a controller-only confirmation setting", err)
				}
			} else if err != nil {
				t.Fatal("remote node without a confirmation override was refused", err)
			}
		})
	}
}

func directLoginResponseBody(t *testing.T, app *testApplication, signer *saml.ServiceProvider, requestID string, assertion *saml.Assertion, signed bool) string {
	t.Helper()
	response := saml.Response{ID: "direct-response", InResponseTo: requestID, Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: app.sp.AcsURL.String(), Issuer: &saml.Issuer{Value: "https://idp.example.test"},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
	element := response.Element()
	if signed {
		context, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal(err)
		}
		element, err = context.SignEnveloped(element)
		if err != nil {
			t.Fatal(err)
		}
	}
	document := etree.NewDocument()
	document.SetRoot(element)
	encoded, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"RelayState": {"test-ticket"}, "SAMLResponse": {base64.StdEncoding.EncodeToString(encoded)}}.Encode()
}

func TestDisabledVPNConfirmationPreservesSAMLAuthorization(t *testing.T) {
	signer, metadata := testIdP(t)
	for _, name := range []string{"valid", "unsigned", "missing-browser", "wrong-browser", "wrong-request", "unassigned-subject"} {
		t.Run(name, func(t *testing.T) {
			app, commands := testApp(t, metadata)
			enabled := false
			app.config.VPNLoginConfirmation = &enabled
			pending := app.tickets["test-ticket"]
			pending.requestID, pending.browserHash = "", [32]byte{}
			handler := app.handler()
			target := app.origin.String() + "/login/test-ticket"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
			cookies := response.Result().Cookies()
			if response.Code != http.StatusFound || len(cookies) != 1 || cookies[0].Name != controller.CookieName("test-ticket") || pending.requestID == "" || pending.active {
				t.Fatal("direct GET did not create only a pending SAML browser binding")
			}
			browser := cookies[0].Value
			if pending.browserHash != sha256.Sum256([]byte(browser)) {
				t.Fatal("direct GET did not bind the new SAML browser cookie")
			}
			requestID, browserHash := pending.requestID, pending.browserHash
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay, httptest.NewRequest(http.MethodGet, target, nil))
			if replay.Code != http.StatusConflict || pending.requestID != requestID || pending.browserHash != browserHash {
				t.Fatal("direct GET replay replaced the existing pending binding")
			}
			select {
			case <-commands:
				t.Fatal("direct GET authorized a VPN connection before SAML verification")
			default:
			}
			assertion := assertionFor(app)
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = requestID
			switch name {
			case "missing-browser":
				browser = ""
			case "wrong-browser":
				browser = "different-browser"
			case "wrong-request":
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "unrelated-request"
			case "unassigned-subject":
				assertion.Subject.NameID.Value = "unassigned-user"
			}
			body := directLoginResponseBody(t, app, signer, requestID, assertion, name != "unsigned")
			result := submitTo(handler, app, body, browser)
			if name == "valid" {
				if result.Code != http.StatusOK {
					t.Fatalf("signed and correlated response refused: HTTP %d", result.Code)
				}
				select {
				case command := <-commands:
					if command != "client-auth-nt 7 2" {
						t.Fatal("wrong connection authorized")
					}
				case <-time.After(time.Second):
					t.Fatal("verified SAML response did not authorize its connection")
				}
				if submitTo(handler, app, body, browser).Code == http.StatusOK {
					t.Fatal("SAML replay accepted with confirmation disabled")
				}
			} else if result.Code == http.StatusOK || pending.active {
				t.Fatal("confirmation opt-out bypassed SAML verification or authorization")
			}
			select {
			case <-commands:
				t.Fatal("invalid or replayed response issued an OpenVPN command")
			default:
			}
		})
	}
}
