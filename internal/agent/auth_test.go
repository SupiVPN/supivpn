// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/saml"
)

func fakeManagement(t *testing.T) (*management, chan string) {
	t.Helper()
	client, server := net.Pipe()
	m := newManagement(client)
	commands := make(chan string, 32)
	t.Cleanup(func() { m.close(); server.Close() })
	go func() {
		scanner := bufio.NewScanner(server)
		var transaction []string
		for scanner.Scan() {
			line := scanner.Text()
			if transaction != nil || strings.HasPrefix(line, "client-auth ") {
				transaction = append(transaction, line)
				if line != "END" {
					continue
				}
				commands <- strings.Join(transaction, "\n")
				transaction = nil
			} else {
				commands <- line
			}
			fmt.Fprintln(server, "SUCCESS: acknowledged")
		}
	}()
	return m, commands
}

func testApp(t *testing.T, metadata *saml.EntityDescriptor) (*testApplication, chan string) {
	t.Helper()
	origin, _ := url.Parse("https://vpn.example.test:8443")
	sp := &saml.ServiceProvider{
		EntityID:          origin.String() + "/saml/metadata",
		MetadataURL:       *origin.ResolveReference(&url.URL{Path: "/saml/metadata"}),
		AcsURL:            *origin.ResolveReference(&url.URL{Path: "/saml/acs"}),
		IDPMetadata:       metadata,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
	}
	a := &testApplication{agent: newAgent(config{AllowedSubjects: []string{"test-user"},
		PendingSeconds: 180, SessionSeconds: 900}, origin), sp: sp}
	m, commands := fakeManagement(t)
	a.attach(m)
	c := &connection{cid: 7, kid: 2, ticket: "test-ticket", requestID: "request-7",
		expires: time.Now().Add(time.Minute), browserHash: sha256.Sum256([]byte("test-browser"))}
	a.connections[c.cid], a.tickets[c.ticket] = c, c
	return a, commands
}

func testIdP(t *testing.T) (*saml.ServiceProvider, *saml.EntityDescriptor) {
	t.Helper()
	// Ephemeral test-only key, never written to disk or logged.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "test-idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signer := &saml.ServiceProvider{Key: key, Certificate: cert,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
	text := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/login"/>
</IDPSSODescriptor></EntityDescriptor>`, base64.StdEncoding.EncodeToString(der))
	md, err := saml.ParseMetadata([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return signer, md
}

func assertionFor(a *testApplication) *saml.Assertion {
	now := time.Now().UTC()
	return &saml.Assertion{
		ID: "assertion-7", Version: "2.0", IssueInstant: now,
		Issuer: saml.Issuer{Value: "https://idp.example.test"},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: string(saml.UnspecifiedNameIDFormat), Value: "test-user"},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: "request-7", Recipient: a.sp.AcsURL.String(), NotOnOrAfter: now.Add(time.Minute),
				},
			}},
		},
		Conditions: &saml.Conditions{NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: a.sp.EntityID}}}},
		AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now, SessionIndex: "test-session"}},
	}
}

func responseBody(t *testing.T, a *testApplication, signer *saml.ServiceProvider, assertion *saml.Assertion, sign bool, tamper bool) string {
	t.Helper()
	response := saml.Response{
		ID: "response-7", InResponseTo: "request-7", Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: a.sp.AcsURL.String(), Issuer: &saml.Issuer{Value: "https://idp.example.test"},
		Status:    saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}},
		Assertion: assertion,
	}
	element := response.Element()
	if sign {
		ctx, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal(err)
		}
		element, err = ctx.SignEnveloped(element)
		if err != nil {
			t.Fatal(err)
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(element)
	text, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		text = strings.ReplaceAll(text, "test-user", "attacker-user")
	}
	return url.Values{"RelayState": {"test-ticket"},
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(text))}}.Encode()
}

func submit(a *testApplication, body, browser string) *httptest.ResponseRecorder {
	return submitTo(a.handler(), a, body, browser)
}

func submitTo(handler http.Handler, a *testApplication, body, browser string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, a.sp.AcsURL.String(), strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if browser != "" {
		r.AddCookie(&http.Cookie{Name: cookieName("test-ticket"), Value: browser})
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestSAMLValidationAndSessionBinding(t *testing.T) {
	signer, md := testIdP(t)
	cases := []string{"valid", "unsigned", "tampered", "wrong-audience", "wrong-request",
		"wrong-issuer", "unassigned-user", "expired-assertion", "expired-pending",
		"missing-confirmation", "wrong-browser", "disconnected", "duplicate-relay"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			a, commands := testApp(t, md)
			assertion := assertionFor(a)
			browser := "test-browser"
			switch name {
			case "wrong-audience":
				assertion.Conditions.AudienceRestrictions[0].Audience.Value = "different-app"
			case "wrong-request":
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "other-request"
			case "wrong-issuer":
				assertion.Issuer.Value = "https://other-idp.example.test"
			case "unassigned-user":
				assertion.Subject.NameID.Value = "unassigned-user"
			case "expired-assertion":
				assertion.Conditions.NotOnOrAfter = time.Now().Add(-time.Hour)
			case "expired-pending":
				a.tickets["test-ticket"].expires = time.Now().Add(-time.Second)
			case "missing-confirmation":
				assertion.Subject.SubjectConfirmations = nil
			case "wrong-browser":
				browser = "different-browser"
			case "disconnected":
				a.removeLocked(a.connections[7])
			}
			body := responseBody(t, a, signer, assertion, name != "unsigned", name == "tampered")
			if name == "duplicate-relay" {
				body += "&RelayState=other-ticket"
			}
			w := submit(a, body, browser)
			if name == "valid" {
				if w.Code != http.StatusOK {
					t.Fatalf("valid response refused: HTTP %d", w.Code)
				}
				if command := <-commands; command != "client-auth-nt 7 2" {
					t.Fatal("wrong connection authorized")
				}
				if submit(a, body, browser).Code == http.StatusOK {
					t.Fatal("assertion replay accepted")
				}
				return
			}
			if w.Code == http.StatusOK {
				t.Fatal("invalid login accepted")
			}
			select {
			case <-commands:
				t.Fatal("invalid login issued an OpenVPN command")
			default:
			}
		})
	}
}

func TestConcurrentAssertionRedemption(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	body := responseBody(t, a, signer, assertionFor(a), true, false)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- submit(a, body, "test-browser").Code }()
	}
	wg.Wait()
	close(statuses)
	success := 0
	for code := range statuses {
		if code == http.StatusOK {
			success++
		}
	}
	if success != 1 || len(commands) != 1 {
		t.Fatal("redemption must authorize exactly once")
	}
}

func TestLoginCreatesBrowserBindingAndRequest(t *testing.T) {
	_, md := testIdP(t)
	a, _ := testApp(t, md)
	a.tickets["test-ticket"].requestID = ""
	r := httptest.NewRequest(http.MethodGet, a.origin.String()+"/login/test-ticket", nil)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("HTTP %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteNoneMode {
		t.Fatal("browser binding cookie missing")
	}
	destination, err := url.Parse(w.Header().Get("Location"))
	if err != nil || destination.Host != "idp.example.test" ||
		destination.Query().Get("RelayState") != "test-ticket" ||
		destination.Query().Get("SAMLRequest") == "" {
		t.Fatal("invalid SSO redirect")
	}
	if _, err := a.Lookup(context.Background(), "test-ticket", sha256.Sum256([]byte(cookies[0].Value))); err != nil {
		t.Fatal(err)
	}
}
