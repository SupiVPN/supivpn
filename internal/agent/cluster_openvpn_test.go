// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

// This is a local UDP relay, not an NLB emulator. It tests reconnect behavior
// against real OpenVPN daemons; AWS target health and Connect remain live tests.
func TestOpenVPNClusterFailover(t *testing.T) {
	for _, cause := range []string{"process-crash", "lease-expiry", "tls-rekey", "session-timeout", "session-reconnect"} {
		t.Run(cause, func(t *testing.T) { testOpenVPNClusterFailover(t, cause) })
	}
}

func testOpenVPNClusterFailover(t *testing.T, cause string) {
	binary, hook := os.Getenv("SUPIVPN_TEST_OPENVPN"), os.Getenv("SUPIVPN_TEST_AGENT")
	if binary == "" {
		t.Skip("requires isolated Linux OpenVPN container")
	}
	if hook == "" {
		t.Fatal("SUPIVPN_TEST_AGENT required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ca := testVPNCertificate(t, dir)
	key := filepath.Join(dir, "wrapping.key")
	issuer := profile.Issuer{OpenVPN: binary}
	if err := issuer.EnsureServerKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	signer, metadata := testIdP(t)
	agents := make([]*testApplication, 2)
	managers := make([]*management, 2)
	stops := make([]func(), 2)
	exits := make([]chan struct{}, 2)
	ports := []int{12194, 12195}
	for i := range 2 {
		socket := filepath.Join(dir, fmt.Sprintf("management-%d.sock", i))
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		config := strings.NewReplacer(
			"port 1194", fmt.Sprintf("port %d", ports[i]),
			"dev supivpn0", fmt.Sprintf("dev supivpn%d", i),
			"server 10.203.0.0 255.255.255.0 nopool", "server 10.200.0.0 255.255.240.0 nopool",
			"/etc/supivpn/tls/crt.pem", filepath.Join(dir, "crt.pem"),
			"extra-certs /etc/supivpn/tls/chain.pem", "# ephemeral test CA",
			"/etc/supivpn/tls/key.pem", filepath.Join(dir, "key.pem"),
			"/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.pem"),
			"/var/lib/supivpn/tls-crypt-v2-server.key", key,
			"/run/supivpn/management.sock", socket,
			"/opt/supivpn/supivpn", hook,
			"keepalive 10 60", "keepalive 1 3",
			"verb 2", "verb 3",
		).Replace(openVPNServerTemplate)
		if cause == "tls-rekey" { config = strings.Replace(config, "reneg-sec 600 600", "reneg-sec 5 5", 1) }
		path := filepath.Join(dir, fmt.Sprintf("server-%d.conf", i))
		writeTestFile(t, path, []byte(config))
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, binary, "--config", path)
		logs := &protocolLog{}
		cmd.Stdout, cmd.Stderr = logs, logs
		if err = cmd.Start(); err != nil {
			cancel()
			t.Fatal("cannot start cluster daemon")
		}
		var once sync.Once
		done := make(chan struct{})
		exits[i] = done
		go func() { _ = cmd.Wait(); close(done) }()
		stop := func() { once.Do(func() { cancel(); <-done }) }
		stops[i] = stop
		t.Cleanup(stop)
		listener.(*net.UnixListener).SetDeadline(time.Now().Add(8 * time.Second))
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal("cluster management unavailable")
		}
		m := newManagement(conn)
		t.Cleanup(m.close)
		managers[i] = m
		if err = m.negotiate(); err != nil {
			t.Fatal(err)
		}
		if err = m.command("state on"); err != nil {
			t.Fatal(err)
		}
		if err = m.command("hold release"); err != nil {
			t.Fatal(err)
		}
		waitProtocol(t, logs, "Initialization Sequence Completed")
		a, _ := testApp(t, metadata)
		a.management.close()
		enableTestGroups(a)
		a.connections, a.tickets = map[uint64]*connection{}, map[string]*connection{}
		a.config = clusterGroupConfig(i)
		a.pools = newPoolAllocator(a.config)
		a.attach(m)
		agents[i] = a
		readyDeadline := time.Now().Add(5*time.Second)
		for !a.loadBalancerReady(context.Background()) {
			if time.Now().After(readyDeadline) { t.Fatalf("initialized real daemon not ready: connected=%v management=%v",m.initialized.Load(),a.Ready(context.Background())) }
			time.Sleep(10*time.Millisecond)
		}
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	upstream := make([]*net.UDPConn, 2)
	var mu sync.Mutex
	selected := 0
	var clientAddr *net.UDPAddr
	var wg sync.WaitGroup
	for i, port := range ports {
		c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if e != nil {
			t.Fatal(e)
		}
		upstream[i] = c
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			buf := make([]byte, 65536)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				mu.Lock()
				addr, active := clientAddr, selected == index
				mu.Unlock()
				if addr != nil && active {
					_, _ = front.WriteToUDP(buf[:n], addr)
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = addr
			to := upstream[selected]
			mu.Unlock()
			_, _ = to.Write(buf[:n])
		}
	}()
	t.Cleanup(func() {
		front.Close()
		for _, c := range upstream {
			c.Close()
		}
		wg.Wait()
	})
	template := strings.Replace(openVPNClientTemplate, "remote supivpn.example.test 1194", fmt.Sprintf("remote 127.0.0.1 %d", front.LocalAddr().(*net.UDPAddr).Port), 1)
	start, end := strings.Index(template, "<ca>"), strings.Index(template, "</ca>")
	template = template[:start] + "<ca>\n" + string(ca) + "</ca>" + template[end+len("</ca>"):]
	out := filepath.Join(dir, "client.ovpn")
	nativeProfileFixture(t, binary, key, template, out)
	auth := filepath.Join(dir, "test-auth")
	writeTestFile(t, auth, []byte("unused-test\nunused-test\n"))
	// Bound handshake recovery when the test kills a peer during TLS rekey.
	clientLog := startProtocolProcess(t, binary, "--config", out, "--auth-user-pass", auth,
		"--hand-window", "5", "--tls-timeout", "1",
		"--dev", "supivpnc", "--dev-type", "tun", "--disable-dco", "--ifconfig-noexec", "--route-noexec",
		"--setenv", "IV_SSO", "webauth", "--verb", "3")
	order := []int{0,1}
    if cause=="session-reconnect" { order[1]=0 }
    var previousCID uint64
    var previousTicket string
    for attempt, i := range order {
        a := agents[i]
		var event clientEvent
		select {
		case event = <-managers[i].events:
		case <-time.After(20 * time.Second):
			clientLog.mu.Lock()
			for _, marker := range []string{"Inactivity timeout", "TLS Error", "AUTH_FAILED", "SIGUSR1", "Initialization Sequence Completed", "AUTH_PENDING received"} {
				t.Logf("client %s: %d", marker, strings.Count(clientLog.b.String(), marker))
			}
			clientLog.mu.Unlock()
			t.Fatal("automatic reconnect did not reach next node")
		}
		if event.kind != "CONNECT" {
			t.Fatal("expected a fresh connection")
		}
		a.handleEvent(event)
		pending := a.connections[event.cid]
        if attempt==1 && cause=="session-reconnect" && (pending.cid==previousCID || pending.ticket==previousTicket) {t.Fatal("expired connection or ticket reused")}
        previousCID,previousTicket=pending.cid,pending.ticket
		w := confirmVPNLogin(t, a.handler(), a.origin, pending.ticket)
		if w.Code != 302 || len(w.Result().Cookies()) != 2 {
			t.Fatal("new SAML login required")
		}
		assertion := groupAssertionFor(a, "admins-vpn", "engineers-production-vpn")
		assertion.ID = fmt.Sprintf("failover-assertion-%d", attempt)
		assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.requestID
		sr := saml.Response{ID: fmt.Sprintf("failover-response-%d", attempt), InResponseTo: pending.requestID, Version: "2.0", IssueInstant: time.Now().UTC(),
			Destination: a.sp.AcsURL.String(), Issuer: &assertion.Issuer, Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
		signing, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signing.SignEnveloped(sr.Element())
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		data, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		body := url.Values{"RelayState": {pending.ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString(data)}}.Encode()
		r := httptest.NewRequest("POST", a.sp.AcsURL.String(), strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(samlLoginCookie(t, w.Result(), pending.ticket))
		result := httptest.NewRecorder()
		a.handler().ServeHTTP(result, r)
		if result.Code != http.StatusOK {
			t.Fatal("SAML authorization failed")
		}
		expected := []string{"10.200.0.2", "10.200.0.129"}[i]
		if pending.address.String() != expected {
			t.Fatal("incorrect failover group address")
		}
		waitProtocol(t, clientLog, "ifconfig "+expected+" 255.255.240.0")
		select {
		case e := <-managers[i].events:
			if e.kind != "ESTABLISHED" {
				t.Fatal("tunnel not established")
			}
			a.handleEvent(e)
		case <-time.After(5 * time.Second):
			t.Fatal("tunnel establishment timed out")
		}
		if attempt == 0 {

            if cause == "session-timeout" || cause == "session-reconnect" {
                now:=time.Now()
                a.now=func()time.Time{return now}
                cancels:=0
                a.remote=&remoteAgent{leaseUntil:now.Add(time.Hour),heartbeatDue:now.Add(time.Hour),
                    publicURL:a.origin.String(),api:remoteAPIFunc(func(_ context.Context,op string,_ agentclient.Request)(*agentapi.Decision,error){
                        if op=="cancel" {cancels++}
                        return nil,nil
                    })}
                pending.expires=now
                a.expire()
                if !pending.closing || !a.readyLocked() || len(a.pools.leases)!=1 || cancels!=0 {
                    t.Fatal("session expiry stopped the daemon or released a live IP")
                }
                // client-kill schedules exit; DISCONNECT can arrive after five seconds.
                select {
                case e:=<-managers[i].events:
                    if e.kind!="DISCONNECT" || e.cid!=pending.cid {t.Fatal("missing real timeout disconnect")}
                    a.handleEvent(e)
                case <-time.After(12*time.Second):
                    t.Fatal("real OpenVPN did not close expired tunnel")
                }
                remoteStepNow(a.agent)
                if cancels!=1 || len(a.pools.leases)!=0 || !a.loadBalancerReady(context.Background()) {
                    t.Fatal("timeout did not release slot while keeping daemon ready")
                }
            }

			if cause == "tls-rekey" {
                previous := pending.expires
                select {
                case e := <-managers[i].events:
                    if e.kind != "REAUTH" || e.cid != pending.cid { t.Fatal("TLS rekey replaced the tunnel") }
                    a.handleEvent(e)
                    if pending.expires != previous { t.Fatal("TLS rekey extended VPN session") }
                case <-time.After(15*time.Second): t.Fatal("TLS rekey missing")
                }
            }
			if cause == "lease-expiry" {
				a.mu.Lock()
				a.remote = &remoteAgent{leaseUntil: time.Now().Add(-time.Second)}
				a.mu.Unlock()
				a.expire()
				select {
				case <-exits[0]:
				case <-time.After(5 * time.Second):
					t.Fatal("lease expiry left the real OpenVPN daemon running")
				}
			}
            if cause=="session-reconnect" {
                a.remote=nil
                a.now=time.Now
                continue // Keep the same daemon and load-balancer target for the fresh login.
            }
			stops[0]()
			select {
			case <-managers[0].done:
			case <-time.After(time.Second):
				t.Fatal("failed node stayed ready")
			}
			if a.loadBalancerReady(context.Background()) {
				t.Fatal("failed node still healthy")
			}
			mu.Lock()
			selected = 1
			mu.Unlock()
		}
	}
}
