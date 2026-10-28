// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
)

var lifecycleGroups = []string{"admins-vpn", "engineers-production-vpn", "testers-vpn", "helpdesk-vpn"}

// Immutable revisions, as in deployment. No mutation of a running allocator.
// Network identity depends on group name, not its position in a policy slice.
func lifecycleConfig(node int, names ...string) config {
	c := config{SAMLGroupsAttribute: "groups", VPNNetwork: "10.200.0.0/20", PendingSeconds: 180, SessionSeconds: 900}
	for index, name := range lifecycleGroups {
		for _, enabled := range names {
			if enabled == name {
				c.GroupPools = append(c.GroupPools, groupPool{GroupName: name, Priority: (index + 1) * 10,
					CIDRs: []string{fmt.Sprintf("10.200.%d.%d/25", index, node*128)}})
			}
		}
	}
	return c
}

type groupLifecycleFixture struct {
	publicLogger *logging.Logger
	pool         *pgxpool.Pool
	stores       [2]*postgres.Store
	signer       *saml.ServiceProvider
	app          *testApplication
	control      *controller.Controller
	agents       [2]*agent
	commands     [2]chan string
}

func newGroupLifecycleFixture(t *testing.T, policy, first, second []string) *groupLifecycleFixture {
	return groupLifecycleWithLegacy(t, policy, first, second, false)
}

func groupLifecycleWithLegacy(t *testing.T, policy, first, second []string, legacy bool) *groupLifecycleFixture {
	t.Helper()
	pool, replica := integrationDatabase(t)
	if _, err := pool.Exec(context.Background(),
		"TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal("cannot reset disposable lifecycle database")
	}
	signer, metadata := testIdP(t)
	app, _ := testApp(t, metadata)
	f := &groupLifecycleFixture{pool: pool, stores: [2]*postgres.Store{postgres.New(pool), postgres.New(replica)}, signer: signer, app: app}
	if legacy {
		for i := range f.stores {
			var err error
			f.stores[i], err = f.stores[i].WithLegacyProfiles([]string{"lifecycle-node-0"})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.setPolicy(t, policy)
	for index, names := range [][]string{first, second} {
		node := fmt.Sprintf("lifecycle-node-%d", index)
		// Real HTTP/JSON agent protocol with an explicitly trusted test identity.
		// IAM signature verification and EC2/NLB are outside this local fixture.
		handler := agentapi.New(f.stores[index], 180*time.Second)
		client, err := agentclient.New("https://login.example.test", agentRoundTrip(func(r *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r.WithContext(agentapi.WithNode(r.Context(), node)))
			return w.Result(), nil
		}), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		if _, err = client.Call(context.Background(), "rotate", agentclient.Request{Generation: "g1"}); err != nil {
			t.Fatal(err)
		}
		a, commands := remoteFixture(t, client)
		a.remote.node = node
		a.config = lifecycleConfig(index, names...)
		a.config.ProfileBinding = "required"
		if legacy && index == 0 {
			a.config.ProfileBinding = "legacy"
		}
		if err := validateAuthorization(a.config); err != nil {
			t.Fatal(err)
		}
		a.pools = newPoolAllocator(a.config)
		f.agents[index], f.commands[index] = a, commands
	}
	return f
}

func (f *groupLifecycleFixture) setPolicy(t *testing.T, names []string) {
	t.Helper()
	c := lifecycleConfig(0, names...)
	var err error
	f.control, err = controller.New(controller.Config{Policy: controllerPolicy(c), PendingSeconds: 180, SessionSeconds: 900},
		f.app.origin, f.app.sp, f.stores[1], time.Now)
	if err != nil {
		t.Fatal(err)
	}
}

type groupLifecycleLogin struct {
	proof   profile.Credential
	node    int
	cid     uint64
	request *http.Request
}

func lifecycleCommand(t *testing.T, ch chan string) string {
	t.Helper()
	select {
	case command := <-ch:
		return command
	case <-time.After(3 * time.Second):
		t.Fatal("management command missing")
		return ""
	}
}

func (f *groupLifecycleFixture) begin(t *testing.T, node int, cid uint64, subject string, members ...string) groupLifecycleLogin {
	assertion := assertionFor(f.app)
	owner := sha256.Sum256([]byte(assertion.Issuer.Value + "\x00" + subject))
	proof := ownedFixtureProof(t, f.stores[0], owner, t.Name()+":"+subject)
	return f.beginWithProof(t, node, cid, subject, proof, members...)
}

func (f *groupLifecycleFixture) beginWithProof(t *testing.T, node int, cid uint64, subject string, proof profile.Credential, members ...string) groupLifecycleLogin {
	t.Helper()
	a := f.agents[node]
	a.handleEvent(clientEvent{kind: "CONNECT", cid: cid, kid: 2, sso: "webauth", proof: proof})
	if command := f.nextCommand(t, node); !strings.Contains(command, "WEB_AUTH:external:") {
		t.Fatalf("expected browser challenge, got %s", command)
	}
	ticket := a.connections[cid].ticket
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.control.Handler().ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), f.publicLogger)))
	})
	w := confirmVPNLogin(t, handler, f.app.origin, ticket)
	if w.Code != http.StatusFound || len(w.Result().Cookies()) != 2 {
		t.Fatal("SAML redirect failed")
	}
	cookie := samlLoginCookie(t, w.Result(), ticket)
	pending, err := f.stores[0].Lookup(context.Background(), ticket, sha256.Sum256([]byte(cookie.Value)))
	if err != nil {
		t.Fatal(err)
	}
	assertion := assertionFor(f.app)
	assertion.ID = fmt.Sprintf("lifecycle-assertion-%d-%d", node, cid)
	assertion.Subject.NameID.Value = subject
	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
	values := make([]saml.AttributeValue, len(members))
	for i, member := range members {
		values[i] = saml.AttributeValue{Value: member}
	}
	assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: []saml.Attribute{{Name: "groups", Values: values}}}}
	response := saml.Response{ID: fmt.Sprintf("lifecycle-response-%d-%d", node, cid), InResponseTo: pending.RequestID,
		Version: "2.0", IssueInstant: time.Now().UTC(), Destination: f.app.sp.AcsURL.String(), Issuer: &assertion.Issuer,
		Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
	signing, err := saml.GetSigningContext(f.signer)
	if err != nil {
		t.Fatal(err)
	}
	element, err := signing.SignEnveloped(response.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(element)
	xml, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{"RelayState": {ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString(xml)}}.Encode()
	request := httptest.NewRequest("POST", f.app.sp.AcsURL.String(), strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	return groupLifecycleLogin{node: node, cid: cid, request: request, proof: proof}
}

func (f *groupLifecycleFixture) callback(t *testing.T, login groupLifecycleLogin, status int) {
	t.Helper()
	w := httptest.NewRecorder()
	f.control.Handler().ServeHTTP(w, login.request.WithContext(logging.WithLogger(login.request.Context(), f.publicLogger)))
	if w.Code != status {
		t.Fatalf("SAML callback: got %d, want %d", w.Code, status)
	}
}

func (f *groupLifecycleFixture) deliver(t *testing.T, login groupLifecycleLogin, group string) {
	t.Helper()
	a := f.agents[login.node]
	command := f.nextCommand(t, login.node)
	c := a.connections[login.cid]
	outcome := "applied"
	if group == "" {
		outcome = "denied"
		if !strings.HasPrefix(command, fmt.Sprintf("client-deny %d 2 ", login.cid)) || c.active {
			t.Fatal("refused group reached the tunnel")
		}
		if _, ok := a.pools.leases[login.cid]; ok {
			t.Fatal("denial allocated an IP")
		}
	} else {
		wantIP := ""
		for index, name := range lifecycleGroups {
			if name == group {
				host := login.node*128 + 1
				if index == 0 && login.node == 0 {
					host++
				}
				wantIP = fmt.Sprintf("10.200.%d.%d", index, host)
			}
		}
		want := fmt.Sprintf("client-auth %d 2\nifconfig-push %s 255.255.240.0\nEND", login.cid, wantIP)
		if command != want || !c.active || c.groupName != group {
			t.Fatalf("wrong authorization for %s: %s", group, command)
		}
	}
	f.settle(t, login)
	var ack string
	if err := f.pool.QueryRow(context.Background(),
		"SELECT coalesce(ack_result,'') FROM supivpn.logins WHERE node_id=$1 AND generation='g1' AND cid=$2 AND kid=2",
		a.remote.node, int64(login.cid)).Scan(&ack); err != nil || ack != outcome {
		t.Fatalf("decision acknowledgement: got %q, want %q", ack, outcome)
	}
}

func (f *groupLifecycleFixture) disconnect(t *testing.T, login groupLifecycleLogin) {
	t.Helper()
	a := f.agents[login.node]
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: login.cid})
	f.settle(t, login)
	if _, ok := a.pools.leases[login.cid]; ok {
		t.Fatal("disconnected IP retained")
	}
}

// The production mailbox is round-robin: an earlier pending browser request
// may consume a tick before this connection registers, fetches, or acknowledges.
func (f *groupLifecycleFixture) nextCommand(t *testing.T, node int) string {
	t.Helper()
	for range 16 {
		remoteStepNow(f.agents[node])
		select {
		case command := <-f.commands[node]:
			return command
		default:
		}
	}
	t.Fatal("management command missing after bounded mailbox steps")
	return ""
}

func (f *groupLifecycleFixture) settle(t *testing.T, login groupLifecycleLogin) {
	t.Helper()
	a := f.agents[login.node]
	for range 16 {
		pending := false
		for _, job := range a.remote.jobs {
			if job.conn.cid == login.cid {
				pending = true
			}
		}
		if !pending {
			return
		}
		remoteStepNow(a)
	}
	t.Fatal("connection ACK/cancel did not settle")
}

// Each revision is a new controller object; both replicas share a real PG18 DB.
// The OpenVPN management peer is simulated, so these are not live tunnel tests.
func TestGroupLifecycleIntegration(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprintf("add-%d-groups-with-mixed-node-revisions", count), func(t *testing.T) {
			old := lifecycleGroups[:2]
			next := lifecycleGroups[:2+count]
			f := newGroupLifecycleFixture(t, old, old, next)
			for index, name := range next[2:] {
				cid := uint64(10 + index)
				before := f.begin(t, 1, cid, "before-"+name, name)
				f.callback(t, before, http.StatusForbidden)
				f.deliver(t, before, "")
				f.disconnect(t, before)
			}
			f.setPolicy(t, next)
			for index, name := range next[2:] {
				oldNode := f.begin(t, 0, uint64(20+index), "member-"+name, name)
				f.callback(t, oldNode, http.StatusAccepted)
				f.deliver(t, oldNode, "") // Missing pool must never fall back.
				// Denied ACK must free the global subject slot even before DISCONNECT.
				newNode := f.begin(t, 1, uint64(30+index), "member-"+name, name)
				f.callback(t, newNode, http.StatusAccepted)
				f.deliver(t, newNode, name)
				f.disconnect(t, newNode)
				f.disconnect(t, oldNode)
			}
			for node := range 2 {
				unchanged := f.begin(t, node, 40, fmt.Sprintf("unchanged-%d", node), lifecycleGroups[0])
				f.callback(t, unchanged, http.StatusAccepted)
				f.deliver(t, unchanged, lifecycleGroups[0])
				f.disconnect(t, unchanged)
			}
		})
		t.Run(fmt.Sprintf("remove-%d-groups-during-browser-login", count), func(t *testing.T) {
			old := lifecycleGroups[:2+count]
			next := lifecycleGroups[:2]
			f := newGroupLifecycleFixture(t, old, old, next)
			active := f.begin(t, 0, 7, "active-member", old[2])
			f.callback(t, active, http.StatusAccepted)
			f.deliver(t, active, old[2])
			var pending []groupLifecycleLogin
			for index, name := range old[2:] {
				pending = append(pending, f.begin(t, 1, uint64(20+index), "pending-"+name, name))
			}
			f.setPolicy(t, next)
			for _, login := range pending {
				f.callback(t, login, http.StatusForbidden)
				f.deliver(t, login, "")
				f.disconnect(t, login)
			}
			members := append(append([]string{}, old[2:]...), next[1])
			fallback := f.begin(t, 1, 40, "remaining-member", members...)
			f.callback(t, fallback, http.StatusAccepted)
			f.deliver(t, fallback, next[1])
			f.disconnect(t, fallback)
			// Characterization of the current limitation: a new policy and a
			// heartbeat do not revoke an already active tunnel on an old node.
			a := f.agents[0]
			before := *a.connections[7]
			if err := f.stores[0].Heartbeat(context.Background(), postgres.Agent{NodeID: a.remote.node, Generation: "g1"}); err != nil {
				t.Fatal(err)
			}
			a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3, proof: active.proof})
			if lifecycleCommand(t, f.commands[0]) != "client-auth-nt 7 3" || !a.connections[7].active ||
				a.connections[7].address != before.address || a.connections[7].expires != before.expires {
				t.Fatal("unexpected active-session behavior after policy removal")
			}
			// The same subject cannot evade the old slot by choosing a remaining group.
			overLimit := f.begin(t, 1, 41, "active-member", next[0])
			f.callback(t, overLimit, http.StatusForbidden)
			f.deliver(t, overLimit, "")
			f.disconnect(t, overLimit)
			f.disconnect(t, active)
			reconnect := f.begin(t, 1, 42, "active-member", next[0])
			f.callback(t, reconnect, http.StatusAccepted)
			f.deliver(t, reconnect, next[0])
		})
	}

	t.Run("queued-grant-is-not-revoked-by-policy-replacement", func(t *testing.T) {
		f := newGroupLifecycleFixture(t, lifecycleGroups, lifecycleGroups, lifecycleGroups[:2])
		oldNode := f.begin(t, 0, 7, "queued-old", "testers-vpn")
		newNode := f.begin(t, 1, 7, "queued-new", "testers-vpn")
		f.callback(t, oldNode, http.StatusAccepted)
		f.callback(t, newNode, http.StatusAccepted)
		f.setPolicy(t, lifecycleGroups[:2])
		// Deliberate characterization, NOT a safe-removal guarantee: a previously
		// committed decision can still be applied by a node retaining that pool.
		f.deliver(t, oldNode, "testers-vpn")
		f.deliver(t, newNode, "")
	})

	t.Run("rollback-to-narrower-policy-does-not-grant-removed-group", func(t *testing.T) {
		f := newGroupLifecycleFixture(t, lifecycleGroups, lifecycleGroups[:2], lifecycleGroups)
		pending := f.begin(t, 1, 7, "rollback-member", "helpdesk-vpn")
		f.setPolicy(t, lifecycleGroups[:2])
		f.callback(t, pending, http.StatusForbidden)
		f.deliver(t, pending, "")
		unchanged := f.begin(t, 0, 8, "unchanged-member", "admins-vpn", "helpdesk-vpn")
		f.callback(t, unchanged, http.StatusAccepted)
		f.deliver(t, unchanged, "admins-vpn")
	})

	t.Run("membership-change-takes-effect-on-next-signed-login", func(t *testing.T) {
		f := newGroupLifecycleFixture(t, lifecycleGroups[:2], lifecycleGroups[:2], lifecycleGroups[:2])
		for index, member := range []string{"admins-vpn", "engineers-production-vpn", "unrelated-vpn"} {
			login := f.begin(t, 0, uint64(7+index), "same-member", member)
			status, group := http.StatusAccepted, member
			if index == 2 {
				status, group = http.StatusForbidden, ""
			}
			f.callback(t, login, status)
			f.deliver(t, login, group)
			f.disconnect(t, login)
		}
	})
}
