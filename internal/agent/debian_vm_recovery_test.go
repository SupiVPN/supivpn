// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration && linux

package agent

import (
	"context"
	"net/http"
	"net/netip"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"supivpn/internal/saml"
)

// All callers first pass requireDebianVM. This client remains running across
// outages and expiry, so a new process cannot hide broken automatic reconnect.
type vmVPN struct{ log *protocolLog }

func startVMVPN(t *testing.T, name string, args ...string) *protocolLog {
	t.Helper()
	cmd := exec.Command(name, args...)
	log := &protocolLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start VM test client")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		// Let explicit-exit-notify release the real UDP session before deleting
		// its namespace. SIGKILL alone would leave it live until keepalive expiry.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if !t.Failed() {
			// Process exit precedes the server's asynchronous DISCONNECT/ack.
			// Keep the namespace alive and require the slot to drain before the
			// next scenario reuses the same user with the setup default of one slot.
			vmWait(t, "disconnected client slot release", 15*time.Second, func() bool {
				return vmCommand(t, "runuser", "-u", "postgres", "--", "psql", "-X",
					"-h", "/var/run/postgresql", "-p", "55433", "-At", "-d", "supivpn_test", "-c",
					"SELECT NOT EXISTS (SELECT 1 FROM supivpn.logins l JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation WHERE l.denial_reason='' AND l.state IN ('decided','acknowledged') AND (l.ack_result IS NULL OR l.ack_result='applied') AND n.fence_state<>'stopped')") == "t"
			})
		}
	})
	return log
}

func (vpn *vmVPN) connections() int {
	vpn.log.mu.Lock()
	defer vpn.log.mu.Unlock()
	return strings.Count(vpn.log.b.String(), "Initialization Sequence Completed")
}

func (vpn *vmVPN) challenge(t *testing.T, previous string) string {
	t.Helper()
	var path string
	pattern := regexp.MustCompile(`https://localhost:8443/login/[A-Za-z0-9_-]+`)
	vmWait(t, "a fresh OpenVPN WEB_AUTH challenge", 90*time.Second, func() bool {
		vpn.log.mu.Lock()
		defer vpn.log.mu.Unlock()
		matches := pattern.FindAllString(vpn.log.b.String(), -1)
		if len(matches) == 0 {
			return false
		}
		path = strings.TrimPrefix(matches[len(matches)-1], "https://localhost:8443")
		return path != previous
	})
	return path
}

func (vpn *vmVPN) canSend() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", "supivpn-vm-client", "curl",
		"--fail", "--silent", "--max-time", "2", "--interface", "supivpnc0", "http://10.203.0.1:18080").Output()
	return err == nil && string(out) == "supivpn-vm-tunnel-ok"
}

func (vpn *vmVPN) traffic(t *testing.T) {
	t.Helper()
	if !vpn.canSend() {
		t.Fatal("TCP payload did not traverse the real tunnel")
	}
}

func (vpn *vmVPN) login(t *testing.T, client *http.Client, signer *saml.ServiceProvider, path string, end time.Time) {
	t.Helper()
	before := vpn.connections()
	vpn.log.mu.Lock()
	logOffset := vpn.log.b.Len()
	vpn.log.mu.Unlock()
	if vpn.canSend() {
		t.Fatal("client carried traffic without fresh SAML authorization")
	}
	vmLoginUntil(t, client, signer, path, http.StatusAccepted, end)
	vmWait(t, "new authorized VPN connection", 30*time.Second, func() bool { return vpn.connections() == before+1 })
	vpn.log.mu.Lock()
	addresses := regexp.MustCompile(`ifconfig (10\.203\.0\.[0-9]+) 255\.255\.255\.0`).FindAllStringSubmatch(vpn.log.b.String()[logOffset:], -1)
	vpn.log.mu.Unlock()
	if len(addresses) == 0 {
		t.Fatal("new connection did not receive an address")
	}
	ip, err := netip.ParseAddr(addresses[len(addresses)-1][1])
	if err != nil || !netip.MustParsePrefix("10.203.0.0/25").Contains(ip) || ip.As4()[3] < 2 || ip.As4()[3] > 126 {
		t.Fatal("signed group did not receive its expected address pool")
	}
	vpn.traffic(t)
}

func vmPairIdentity(t *testing.T) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, unit := range []string{"supivpn-node", "supivpn-openvpn"} {
		result[unit] = vmCommand(t, "systemctl", "show", "--property=MainPID,InvocationID", unit)
	}
	return result
}

func vmGeneration(t *testing.T) string {
	t.Helper()
	state := vmJSON(t, "/var/lib/supivpn-node/generation.json")
	generation, ok := state["current"].(string)
	if !ok || generation == "" || state["next"] != nil {
		t.Fatal("node has no committed generation")
	}
	return generation
}

func vmAssertLoginUnavailable(t *testing.T, client *http.Client) {
	t.Helper()
	if vmReady(client, 8443) {
		t.Fatal("controller claims readiness during dependency outage")
	}
	resp, err := client.Get("https://localhost:8443/profile")
	if err != nil {
		return // The controller itself is stopped.
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("controller did not refuse profile login during database outage")
	}
}

func vmOutageRecovery(t *testing.T, client *http.Client, signer *saml.ServiceProvider, unit string) {
	t.Helper()
	if !vmReady(client, 8443) || !vmReady(client, 9443) {
		t.Fatal("outage scenario requires healthy controller and node")
	}
	// Earlier independent crash scenarios consume the same systemd start budget.
	// Reset counters only at this healthy boundary, never during outage/recovery.
	// Keep the installed rate limits and all production lease timings unchanged.
	vmCommand(t, "systemctl", "reset-failed", "supivpn-node", "supivpn-openvpn")
	vpn := vmStartVPN(t, client, signer)
	path := vpn.challenge(t, "")
	vpn.login(t, client, signer, path, time.Time{})
	before, generation := vmPairIdentity(t), vmGeneration(t)
	controllerPID := vmPID(t, "supivpn-controller")
	// Restore the task-owned guest dependency even when an assertion fails.
	t.Cleanup(func() { vmCommand(t, "systemctl", "start", unit) })
	t.Cleanup(func() {
		if t.Failed() {
			for _, service := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-controller", "postgresql@18-supivpn"} {
				t.Log(service, vmCommand(t, "systemctl", "show", "--property=ActiveState,SubState,Result,NRestarts,ExecMainStatus", service))
			}
		}
	})
	vmCommand(t, "systemctl", "stop", unit)
	vmAssertLoginUnavailable(t, client)
	for i := 0; i < 4; i++ {
		vpn.traffic(t)
		time.Sleep(2 * time.Second)
	}
	vmCommand(t, "systemctl", "start", unit)
	vmWait(t, "controller after short outage", 30*time.Second, func() bool { return vmReady(client, 8443) })
	vpn.traffic(t)
	if !reflect.DeepEqual(before, vmPairIdentity(t)) || generation != vmGeneration(t) || vpn.connections() != 1 {
		t.Fatal("short outage restarted the pair, rotated its generation or reconnected the client")
	}
	// Observe a real renewal before the prolonged outage, without altering either
	// the agent's 40-second deadline or the database's 60-second lease.
	vmWait(t, "lease renewal after short outage", 25*time.Second, func() bool {
		return vmCommand(t, "runuser", "-u", "postgres", "--", "psql", "-X", "-h", "/var/run/postgresql", "-p", "55433", "-At", "-d", "supivpn_test", "-c",
			"SELECT EXISTS (SELECT 1 FROM supivpn.nodes WHERE node_id='node-a' AND lease_expires_at>clock_timestamp()+interval '55 seconds')") == "t"
	})
	t.Log("short outage preserved the live tunnel, processes and generation; heartbeat resumed")
	vmCommand(t, "systemctl", "stop", unit)
	stopped := time.Now()
	vmAssertLoginUnavailable(t, client)
	vmWait(t, "lease expiry closing the old VPN pair", 50*time.Second, func() bool {
		return !vmReady(client, 9443) && vmPairIdentity(t)["supivpn-openvpn"] != before["supivpn-openvpn"] && !vpn.canSend()
	})
	// Keep the dependency unavailable beyond both deadlines. A restarted daemon
	// may wait in management hold, but must never pass readiness or traffic.
	for time.Since(stopped) < 65*time.Second {
		if vmReady(client, 9443) || vpn.canSend() {
			t.Fatal("node resumed service while its controller lease was unavailable")
		}
		time.Sleep(time.Second)
	}
	vmCommand(t, "systemctl", "start", unit)
	vmWait(t, "automatic pair recovery after prolonged outage", 90*time.Second, func() bool {
		return vmReady(client, 8443) && vmReady(client, 9443)
	})
	if generation == vmGeneration(t) || reflect.DeepEqual(before, vmPairIdentity(t)) {
		t.Fatal("prolonged outage reused the old node generation or processes")
	}
	if unit == "postgresql@18-supivpn" && vmPID(t, "supivpn-controller") != controllerPID {
		t.Fatal("database recovery required a controller restart")
	}
	next := vpn.challenge(t, path)
	if vpn.connections() != 1 {
		t.Fatal("recovery authorized the client without a new SAML login")
	}
	vpn.login(t, client, signer, next, time.Time{})
	vmCheckSandbox(t)
	t.Log("prolonged outage failed closed; services recovered automatically with a fresh generation and SAML login")
}

func vmSessionRecovery(t *testing.T, client *http.Client, signer *saml.ServiceProvider) {
	t.Helper()
	vpn := vmStartVPN(t, client, signer)
	before, generation := vmPairIdentity(t), vmGeneration(t)
	path := vpn.challenge(t, "")
	// Repeated expiration and login must release each authorization under the
	// setup default of one slot, without changing the installed policy.
	for i := 0; i < 2; i++ {
		end := time.Now().UTC().Add(20 * time.Second).Truncate(time.Second)
		vpn.login(t, client, signer, path, end)
		for time.Now().Before(end.Add(-5 * time.Second)) {
			vpn.traffic(t)
			time.Sleep(time.Second)
		}
		next := vpn.challenge(t, path)
		if time.Now().Before(end) || vpn.connections() != i+1 || vpn.canSend() {
			t.Fatal("session ended too early or reconnected without fresh authorization")
		}
		if !vmReady(client, 9443) || !reflect.DeepEqual(before, vmPairIdentity(t)) || generation != vmGeneration(t) {
			t.Fatal("single-session expiry restarted or disabled the node")
		}
		path = next
	}
	vpn.login(t, client, signer, path, time.Time{})
	t.Log("two signed IdP session deadlines closed only their tunnels; the same client reauthenticated and slots were released")
}
