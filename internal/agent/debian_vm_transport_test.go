// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration && linux

package agent

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"supivpn/internal/saml"
)

func vmTransportProfile(t *testing.T, data []byte, transport string) []byte {
	t.Helper()
	if transport == "fallback" {
		return bytes.Clone(data)
	}
	proto := "proto udp4"
	if transport == "tcp" {
		proto = "proto tcp4-client"
	}
	blocks := regexp.MustCompile("(?s)<connection>.*?</connection>\\n?")
	for _, block := range blocks.FindAll(data, -1) {
		if bytes.Contains(block, []byte(proto)) {
			// Single-transport fixtures use the pre-fallback profile layout.
			// Leaving a connection block would freeze per-connection defaults
			// before the client's explicit-exit-notify command-line option.
			block = bytes.ReplaceAll(block, []byte("<connection>\n"), nil)
			block = bytes.ReplaceAll(block, []byte("</connection>\n"), nil)
			return append(blocks.ReplaceAll(data, nil), block...)
		}
	}
	t.Fatal("requested transport absent from issued profile")
	return nil
}

// Keep a separate namespace and the same client process across reconnects.
// Never print profiles, client output, proofs, tickets or assertions.
func vmTransportClient(t *testing.T, data []byte, slot int, subject string) *vmVPN {
	t.Helper()
	ns, host, peer := fmt.Sprintf("supi-t%d", slot), fmt.Sprintf("supi-h%d", slot), fmt.Sprintf("supi-p%d", slot)
	serverIP, clientIP := fmt.Sprintf("192.0.2.%d", slot*4+1), fmt.Sprintf("192.0.2.%d", slot*4+2)
	vmCommand(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", ns).Run() })
	vmCommand(t, "ip", "link", "add", host, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", host).Run() })
	vmCommand(t, "ip", "link", "set", peer, "netns", ns)
	vmCommand(t, "ip", "addr", "add", serverIP+"/30", "dev", host)
	vmCommand(t, "ip", "link", "set", host, "up")
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", clientIP + "/30", "dev", peer}, {"link", "set", peer, "up"}} {
		vmCommand(t, "ip", append([]string{"-n", ns}, args...)...)
	}
	data = bytes.ReplaceAll(data, []byte("remote localhost "), []byte("remote "+serverIP+" "))
	path := filepath.Join(t.TempDir(), "client.ovpn")
	vmWrite(t, path, data, 0600, "")
	args := []string{"netns", "exec", ns, "/usr/sbin/openvpn", "--config", path,
		"--dev", "supivpnc0", "--dev-type", "tun", "--disable-dco",
		"--connect-retry", "1", "2", "--setenv", "IV_SSO", "webauth", "--verb", "3"}
	if !bytes.Contains(data, []byte("proto tcp4-client")) {
		args = append(args, "--explicit-exit-notify", "1")
	}
	cmd := exec.Command("ip", args...)
	log := &protocolLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if cmd.Start() != nil {
		t.Fatal("cannot start isolated transport client")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	t.Cleanup(stop)
	return &vmVPN{log: log, namespace: ns, subject: subject, stop: stop}
}

const vmActiveLogins = " FROM supivpn.logins l JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation WHERE l.denial_reason='' AND l.state IN ('decided','acknowledged') AND (l.ack_result IS NULL OR l.ack_result='applied') AND n.fence_state<>'stopped'"

func vmTransportSlots(t *testing.T, udp, tcp int) {
	t.Helper()
	vmTransportSlotsWithin(t, udp, tcp, 20*time.Second)
}

func vmTransportSlotsWithin(t *testing.T, udp, tcp int, timeout time.Duration) {
	t.Helper()
	want := fmt.Sprintf("%d|%d", udp, tcp)
	var last string
	defer func() {
		if t.Failed() && regexp.MustCompile(`^[0-9]+\|[0-9]+$`).MatchString(last) {
			t.Logf("session slots UDP|TCP: got %s, want %s", last, want)
		}
	}()
	vmWait(t, "exact UDP/TCP session slots", timeout, func() bool {
		last = vmDatabaseQuery(t, "SELECT count(*) FILTER (WHERE cid<4611686018427387904),count(*) FILTER (WHERE cid>=4611686018427387904)"+vmActiveLogins)
		return last == want
	})
}

func vmTransportIdentities(t *testing.T) map[string]string {
	t.Helper()
	out := vmPairIdentity(t)
	out["supivpn-openvpn-tcp"] = vmCommand(t, "systemctl", "show", "--property=MainPID,InvocationID", "supivpn-openvpn-tcp")
	return out
}

func vmTransportRekeys(t *testing.T) map[string]int {
	t.Helper()
	result := map[string]int{}
	raw := vmCommand(t, "journalctl", "--unit=supivpn-node", "--output=cat", "--no-pager")
	for _, line := range strings.Split(raw, "\n") {
		var e struct{ Event, Transport string }
		if json.Unmarshal([]byte(line), &e) == nil && e.Event == "vpn.tls_reauthenticated" {
			result[e.Transport]++
		}
	}
	return result
}

// Exercise the packaged server-initiated rekey policy with a shorter interval.
// Client, handshake, keepalive, admission and lease settings stay unchanged.
func vmTransportServerRekey(t *testing.T, client *http.Client, seconds int) {
	t.Helper()
	paths := []string{"/etc/supivpn/node/openvpn.conf", "/etc/supivpn/node/openvpn-tcp.conf"}
	originals := make([][]byte, len(paths))
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || bytes.Count(data, []byte("reneg-sec 600 600")) != 1 {
			t.Fatal("missing packaged server rekey setting")
		}
		originals[i] = data
		vmWrite(t, path, bytes.ReplaceAll(data, []byte("reneg-sec 600 600"), []byte(fmt.Sprintf("reneg-sec %d %d", seconds, seconds))), 0600, "")
	}
	t.Cleanup(func() {
		for i, path := range paths {
			vmWrite(t, path, originals[i], 0600, "")
		}
		vmCommand(t, "systemctl", "restart", "supivpn-node")
		vmWait(t, "restore packaged rekey settings", 50*time.Second, func() bool { return vmReady(client, 9443) })
	})
	vmCommand(t, "systemctl", "restart", "supivpn-node")
	vmWait(t, "server-initiated rekey fixture", 50*time.Second, func() bool { return vmReady(client, 9443) })
}

func vmTransportOutage(t *testing.T, client *http.Client, signer *saml.ServiceProvider, unit string, long bool) {
	t.Helper()
	vmTransportServerRekey(t, client, 60)
	vmResetCrashBudget(t, client)
	vmCommand(t, "systemctl", "reset-failed", "supivpn-openvpn-tcp")
	udpData := vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "transport-udp"), "udp")
	tcpData := vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "transport-tcp"), "tcp")
	u := vmTransportClient(t, udpData, 1, "transport-udp")
	v := vmTransportClient(t, tcpData, 2, "transport-tcp")
	up, tp := u.challenge(t, ""), v.challenge(t, "")
	u.login(t, client, signer, up, time.Time{})
	v.login(t, client, signer, tp, time.Time{})
	vmTransportSlots(t, 1, 1)
	t.Log("both transports authorized with real payload")
	before, generation, rekeys := vmTransportIdentities(t), vmGeneration(t), vmTransportRekeys(t)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, service := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-openvpn-tcp"} {
			t.Log(service, vmCommand(t, "systemctl", "show", "--property=ActiveState,SubState,Result,NRestarts,ExecMainStatus", service))
		}
		for transport, vpn := range map[string]*vmVPN{"udp": u, "tcp": v} {
			for _, marker := range []string{"AUTH_FAILED", "SIGUSR1[soft,ping-restart]", "SIGUSR1[soft,server-pushed-connection-reset]", "TLS Error", "SIGTERM"} {
				if vpn.log.contains(marker) {
					t.Log("client diagnostic:", transport, marker)
				}
			}
		}
	})
	vmWait(t, "both transports rekeyed with unchanged SAML sessions", 80*time.Second, func() bool {
		now := vmTransportRekeys(t)
		return now["udp"] > rekeys["udp"] && now["tcp"] > rekeys["tcp"]
	})
	u.traffic(t)
	v.traffic(t)
	t.Log("both transports passed payload after their first rekeys")
	vmTransportSlots(t, 1, 1)
	// Begin the outage shortly before the next scheduled rekey. A full minute
	// also leaves room for normal browser authentication after node recovery;
	// a 20-second rekey can overlap the pending initial handshake in this VM.
	for until := time.Now().Add(35 * time.Second); time.Now().Before(until); {
		u.traffic(t)
		v.traffic(t)
		time.Sleep(2 * time.Second)
	}
	vmWait(t, "fresh shared lease before outage", 25*time.Second, func() bool {
		return vmDatabaseQuery(t, "SELECT EXISTS (SELECT 1 FROM supivpn.nodes WHERE node_id='node-a' AND lease_expires_at>clock_timestamp()+interval '55 seconds')") == "t"
	})
	t.Cleanup(func() { vmDependency(t, unit, true) })
	rekeys = vmTransportRekeys(t)
	vmDependency(t, unit, false)
	stopped := time.Now()
	vmAssertLoginUnavailable(t, client)
	for i := 0; i < 12; i++ {
		u.traffic(t)
		v.traffic(t)
		time.Sleep(2 * time.Second)
	}
	t.Log("both transports passed payload during dependency outage")
	vmWait(t, "both transports rekey during dependency outage", 6*time.Second, func() bool {
		now := vmTransportRekeys(t)
		return now["udp"] > rekeys["udp"] && now["tcp"] > rekeys["tcp"]
	})
	if !long {
		// Exercise cancellation on each transport across the two dependencies.
		gone, survivor, data, subject, remainingUDP, remainingTCP := v, u, tcpData, "transport-tcp", 1, 0
		if unit != "supivpn-controller" {
			gone, survivor, data, subject, remainingUDP, remainingTCP = u, v, udpData, "transport-udp", 0, 1
		}
		gone.stop()
		vmDependency(t, unit, true)
		vmWait(t, "short outage recovery", 30*time.Second, func() bool { return vmReady(client, 8443) })
		t.Logf("dependency outage through restored readiness: %.1fs", time.Since(stopped).Seconds())
		vmTransportSlots(t, remainingUDP, remainingTCP)
		t.Log("outage cancellation committed; surviving transport retained its slot")
		if !reflect.DeepEqual(before, vmTransportIdentities(t)) || generation != vmGeneration(t) || survivor.connections() != 1 {
			t.Fatal("short outage disturbed the surviving transport or node generation")
		}
		survivor.traffic(t)
		replacement := vmTransportClient(t, data, 3, subject)
		replacement.login(t, client, signer, replacement.challenge(t, ""), time.Time{})
		vmTransportSlots(t, 1, 1)
		t.Log("same owner reconnected after the outage")
		replacement.stop()
		survivor.stop()
		vmTransportSlots(t, 0, 0)
		t.Log("both transports rekeyed; disconnect during outage released only its slot and the same owner reconnected")
		return
	}
	vmWait(t, "shared lease expiry closes both live tunnels", 50*time.Second, func() bool {
		return !vmReady(client, 9443) && !u.canSend() && !v.canSend() &&
			vmTransportIdentities(t)["supivpn-openvpn"] != before["supivpn-openvpn"] &&
			vmTransportIdentities(t)["supivpn-openvpn-tcp"] != before["supivpn-openvpn-tcp"]
	})
	for time.Since(stopped) < 65*time.Second {
		if vmReady(client, 9443) || u.canSend() || v.canSend() {
			t.Fatal("a transport passed traffic or readiness after shared lease expiry")
		}
		time.Sleep(time.Second)
	}
	vmDependency(t, unit, true)
	vmWait(t, "automatic dual transport recovery", 90*time.Second, func() bool {
		return vmReady(client, 8443) && vmReady(client, 9443)
	})
	if generation == vmGeneration(t) {
		t.Fatal("lease expiry retained the stale generation")
	}
	u.login(t, client, signer, u.challenge(t, up), time.Time{})
	v.login(t, client, signer, v.challenge(t, tp), time.Time{})
	vmTransportSlots(t, 1, 1)
	u.stop()
	v.stop()
	vmTransportSlots(t, 0, 0)
	t.Log("lease expiry stopped both transports; unchanged clients recovered with fresh SAML and no stale slots")
}

func TestDebianVMTransportLifecycle(t *testing.T) {
	requireDebianVM(t)
	if os.Getenv("SUPIVPN_TEST_VM_TRANSPORT") != "dual" {
		t.Skip("requires fresh TCP-enabled setup")
	}
	signer, metadata := testIdP(t)
	md, err := xml.Marshal(metadata)
	if err != nil {
		t.Fatal("cannot encode synthetic IdP")
	}
	vmWrite(t, "/etc/supivpn/controller/idp-metadata.xml", md, 0640, "root:supivpn-controller")
	vmWrite(t, "/etc/supivpn/node/idp-metadata.xml", md, 0600, "")
	client := vmHTTPS(t)
	vmCommand(t, "systemctl", "restart", "supivpn-controller")
	vmWait(t, "fresh controller", 30*time.Second, func() bool { return vmReady(client, 8443) })
	vmCommand(t, "systemctl", "start", "supivpn-node")
	vmWait(t, "fresh dual-transport setup", 50*time.Second, func() bool {
		return vmReady(client, 9443) && vmPID(t, "supivpn-openvpn-tcp") != "0"
	})
	vmCommand(t, "supivpn-setup", "check")
	vmCheckSandbox(t)
	vmCheckBoundSandbox(t)
	listener, err := net.Listen("tcp", "10.203.0.1:18080")
	if err != nil {
		t.Fatal("cannot start tunnel payload receiver")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "supivpn-vm-tunnel-ok")
	}), ReadHeaderTimeout: 3 * time.Second}
	t.Cleanup(func() { server.Close() })
	go func() { _ = server.Serve(listener) }()
	check := func(name string, f func(*testing.T)) {
		t.Helper()
		vmResetCrashBudget(t, client)
		vmCommand(t, "systemctl", "reset-failed", "supivpn-openvpn-tcp")
		if !t.Run(name, f) {
			t.FailNow()
		}
		vmTransportSlots(t, 0, 0)
	}
	check("disable-and-reenable", func(t *testing.T) {
		original := vmLogin(t, client, signer, "/profile", 200)
		oldUDP := vmTransportProfile(t, original, "udp")
		paths := []string{"/etc/supivpn/node/agent.json", "/etc/supivpn/controller/controller.json"}
		saved := [][]byte{}
		for _, path := range paths {
			data, e := os.ReadFile(path)
			if e != nil {
				t.Fatal("missing setup configuration")
			}
			saved = append(saved, data)
		}
		agentConfig, public := vmJSON(t, paths[0]), vmJSON(t, paths[1])
		delete(agentConfig, "tcp_management_socket")
		public["profile"].(map[string]any)["tcp_fallback_port"] = 0
		vmSaveJSON(t, paths[0], agentConfig, 0600, "")
		vmSaveJSON(t, paths[1], public, 0640, "root:supivpn-controller")
		const tcpPath = "/etc/supivpn/node/openvpn-tcp.conf"
		if os.Rename(tcpPath, tcpPath+".test-disabled") != nil {
			t.Fatal("cannot disable optional configuration")
		}
		vmCommand(t, "systemctl", "restart", "supivpn-controller", "supivpn-node")
		vmWait(t, "UDP-only after disabling TCP", 45*time.Second, func() bool { return vmReady(client, 8443) && vmReady(client, 9443) })
		if vmPID(t, "supivpn-openvpn-tcp") != "0" {
			t.Fatal("disabled TCP process remained active")
		}
		if c, e := net.DialTimeout("tcp", "127.0.0.1:443", time.Second); e == nil {
			c.Close()
			t.Fatal("disabled TCP listener remained reachable")
		}
		if bytes.Contains(vmLogin(t, client, signer, "/profile", 200), []byte("<connection>")) {
			t.Fatal("disabled TCP still advertised")
		}
		for name, data := range map[string][]byte{"previous-dual": original, "previous-UDP-only": oldUDP} {
			if !t.Run(name, func(t *testing.T) {
				v := vmTransportClient(t, data, 1, "")
				v.login(t, client, signer, v.challenge(t, ""), time.Time{})
				vmTransportSlots(t, 1, 0)
				v.stop()
				// An unmodified dual profile may not send UDP exit-notify.
				// The daemon must confirm absence through its normal keepalive.
				vmTransportSlotsWithin(t, 0, 0, 150*time.Second)
			}) {
				t.FailNow()
			}
		}
		vmWrite(t, paths[0], saved[0], 0600, "")
		vmWrite(t, paths[1], saved[1], 0640, "root:supivpn-controller")
		if os.Rename(tcpPath+".test-disabled", tcpPath) != nil {
			t.Fatal("cannot restore optional configuration")
		}
		vmCommand(t, "systemctl", "restart", "supivpn-controller", "supivpn-node")
		vmWait(t, "TCP reenabled", 50*time.Second, func() bool {
			return vmReady(client, 8443) && vmReady(client, 9443) && vmPID(t, "supivpn-openvpn-tcp") != "0"
		})
		v := vmTransportClient(t, vmTransportProfile(t, original, "tcp"), 1, "")
		v.login(t, client, signer, v.challenge(t, ""), time.Time{})
		vmTransportSlots(t, 0, 1)
		v.stop()
		vmTransportSlots(t, 0, 0)
		vmCommand(t, "supivpn-setup", "check")
	})
	check("established-UDP-loss", func(t *testing.T) {
		data := vmLogin(t, client, signer, "/profile", 200)
		v := vmTransportClient(t, data, 1, "")
		path := v.challenge(t, "")
		v.login(t, client, signer, path, time.Time{})
		vmTransportSlots(t, 1, 0)
		// Drop both directions after proving payload, without process restart
		// or accelerated keepalive/session-limit settings.
		const table = "supivpn_test_udp_loss"
		vmCommand(t, "nft", "add", "table", "ip", table)
		t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip", table).Run() })
		vmCommand(t, "nft", "add", "chain", "ip", table, "input", "{ type filter hook input priority -10; policy accept; }")
		vmCommand(t, "nft", "add", "chain", "ip", table, "output", "{ type filter hook output priority -10; policy accept; }")
		vmCommand(t, "nft", "add", "rule", "ip", table, "input", "udp", "dport", "1194", "drop")
		vmCommand(t, "nft", "add", "rule", "ip", table, "output", "udp", "sport", "1194", "drop")
		lost := time.Now()
		next := v.challenge(t, path)
		t.Logf("new browser challenge after established UDP loss: %.1fs", time.Since(lost).Seconds())
		body, status := vmLoginResponse(t, client, signer, next, time.Time{}, "")
		if status != http.StatusAccepted || !bytes.Contains(body, []byte("retry once in 60 seconds")) {
			t.Fatal("fallback did not schedule its bounded retry")
		}
		retryStart := time.Now()
		vmWait(t, "temporary TCP refusal after server-side wait", 75*time.Second, func() bool { return v.log.contains("AUTH_FAILED,TEMP") })
		if v.canSend() || v.connections() != 1 {
			t.Fatal("temporary refusal carried traffic")
		}
		retry := v.challenge(t, next)
		if time.Since(retryStart) < 55*time.Second {
			t.Fatal("client ignored temporary refusal backoff")
		}
		vmTransportSlots(t, 0, 0)
		v.login(t, client, signer, retry, time.Time{})
		if v.connections() != 2 {
			t.Fatal("client was replaced or skipped authorization")
		}
		vmTransportSlots(t, 0, 1)
		t.Logf("same client recovered on TCP after fresh SAML: %.1fs from UDP loss", time.Since(lost).Seconds())
		v.stop()
		vmTransportSlots(t, 0, 0)
	})
	check("rekey-without-outage", func(t *testing.T) {
		vmTransportServerRekey(t, client, 20)
		u := vmTransportClient(t, vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "steady-udp"), "udp"), 1, "steady-udp")
		v := vmTransportClient(t, vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "steady-tcp"), "tcp"), 2, "steady-tcp")
		u.login(t, client, signer, u.challenge(t, ""), time.Time{})
		v.login(t, client, signer, v.challenge(t, ""), time.Time{})
		before := vmTransportRekeys(t)
		for until := time.Now().Add(125 * time.Second); time.Now().Before(until); {
			u.traffic(t)
			v.traffic(t)
			time.Sleep(time.Second)
		}
		after := vmTransportRekeys(t)
		if after["udp"]-before["udp"] < 5 || after["tcp"]-before["tcp"] < 5 {
			t.Fatal("insufficient independent rekeys in steady-state comparison")
		}
		u.stop()
		v.stop()
		vmTransportSlots(t, 0, 0)
	})
	database := "postgresql@18-supivpn"
	if vmRemoteDatabase() {
		database = "external-database"
	}
	for _, unit := range []string{"supivpn-controller", database} {
		for _, long := range []bool{false, true} {
			check(fmt.Sprintf("outage-%s-prolonged-%t", unit, long), func(t *testing.T) { vmTransportOutage(t, client, signer, unit, long) })
		}
	}
	check("independent-session-expiry", func(t *testing.T) {
		u := vmTransportClient(t, vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "expiry-udp"), "udp"), 1, "expiry-udp")
		v := vmTransportClient(t, vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "expiry-tcp"), "tcp"), 2, "expiry-tcp")
		up, tp := u.challenge(t, ""), v.challenge(t, "")
		u.login(t, client, signer, up, time.Now().Add(25*time.Second))
		v.login(t, client, signer, tp, time.Time{})
		before, generation := vmTransportIdentities(t), vmGeneration(t)
		up = u.challenge(t, up)
		v.traffic(t)
		vmTransportSlots(t, 0, 1)
		u.login(t, client, signer, up, time.Time{})
		v.stop()
		vmTransportSlots(t, 1, 0)
		w := vmTransportClient(t, vmTransportProfile(t, vmLoginAs(t, client, signer, "/profile", 200, time.Time{}, "expiry-tcp"), "tcp"), 3, "expiry-tcp")
		wp := w.challenge(t, "")
		w.login(t, client, signer, wp, time.Now().Add(25*time.Second))
		wp = w.challenge(t, wp)
		u.traffic(t)
		vmTransportSlots(t, 1, 0)
		w.login(t, client, signer, wp, time.Time{})
		if !reflect.DeepEqual(before, vmTransportIdentities(t)) || generation != vmGeneration(t) {
			t.Fatal("individual expiry restarted the shared node")
		}
		u.stop()
		w.stop()
		vmTransportSlots(t, 0, 0)
	})
	// Setup deliberately leaves boot enablement to the operator. Mirror the
	// documented acceptance step for the local database as well as SupiVPN.
	if !vmRemoteDatabase() {
		vmCommand(t, "systemctl", "enable", "postgresql@18-supivpn")
	}
	vmCommand(t, "systemctl", "enable", "supivpn-controller", "supivpn-node")
	vmCheckSandbox(t)
	vmCheckBoundSandbox(t)
}
