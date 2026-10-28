# UDP with optional TCP fallback

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

**Available since v0.9.0.** UDP remains the default. TCP is an explicit
operator choice and does not replace profile ownership or SAML authorization.

## Enable TCP in a new Debian setup

The default setup example has TCP disabled:

```json
"tcp_fallback": {"enabled": false, "port": 443}
```

To enable it, change `enabled` to `true` in the input to `supivpn-setup`:

```json
"tcp_fallback": {"enabled": true, "port": 443}
```

Omitting the block also disables TCP. A missing port defaults to 443. Review
`supivpn-setup plan` before initialization. TCP/443 must be free on the VPN
address; this is OpenVPN over TCP, not HTTPS, and cannot share the same listener
with a web server. Allow that port in the host and upstream firewalls.

Setup keeps one agent, node ID, controller connection, generation journal and
address allocator. It adds an unmodified OpenVPN TCP process, its private Unix
management socket and a second TUN interface. The agent manages both processes.
With TCP disabled, no TCP listener, second management socket, route hook or
TCP firewall allowance is generated.

## Shared pool, without a fixed split

Both transports draw addresses from the same configured group pools. Enabling
TCP neither reserves half the addresses nor adds a second group subnet. Existing
network/gateway/broadcast exclusions are unchanged. All available group addresses
can be occupied by UDP clients, TCP clients, or any mixture.

Both TUN interfaces use the configured VPN network and gateway. A host route
(`/32`) selects the correct interface for each admitted client. OpenVPN's
supported `learn-address` hook installs that route only for the address supplied
by the agent; other source addresses and routed subnets remain rejected.
`client-disconnect` removes the route before OpenVPN notifies the agent that the
connection is gone. Delayed internal-route garbage collection does not delete
host routes: the address may already belong to a new connection.

The hook uses fixed `iproute2` commands without a shell or inherited client
environment. It refuses foreign/conflicting host routes and deletes only its
own route on its configured TUN interface. Failures are reported as
`network.route_refused`; do not disable source validation to work around them.
Route changes use OpenVPN's existing `CAP_NET_ADMIN`; the agent does not gain
it. The optional TCP service also needs `CAP_NET_BIND_SERVICE` for port 443.
`disable-dco` remains required for this supported configuration.

The shared pool described here belongs to one node. HA nodes retain their own
non-overlapping pool ranges; TCP does not introduce another partition within
them. See [HA transport and load-balancer requirements](HA.md#udp-and-tcp-in-an-ha-deployment).

Group policy, profile state and per-user connection limits apply across both
transports. Two simultaneous connections receive different addresses even if
their OpenVPN processes assign the same local client number. A management failure
in either process stops the shared node so generation rotation cannot leave
unaccounted tunnels running in the other process.

## Profiles and manual configuration

The public controller's `profile.tcp_fallback_port` defaults to zero (disabled).
Set it to `443` to issue ordered connection blocks: UDP at `profile.port`, then
TCP/443. Set the agent's `tcp_management_socket` only when the corresponding
TCP daemon is configured. Setup generates these settings together; changing the
controller alone does not create a listener.

Generated connection blocks wait three seconds for an unresponsive endpoint
before trying the next option. DNS, connection retry scheduling and the TCP/TLS
handshake add latency; this is not a three-second end-to-end login guarantee.
Once the server responds, the existing 180-second handshake window remains
available for browser SAML/MFA. It is not reduced to the endpoint polling timeout.

Existing installations should preserve their current group ranges, node ID,
state directory, wrapping key, TLS material and UDP port. Do not rerun first-time
setup over a working installation. In a maintenance window:

1. Keep the existing UDP configuration and add a distinct TCP management socket
   in the same private directory to the agent configuration.
2. Add both hooks below to the UDP configuration, preserving its other options:

   ```text
   learn-address "/usr/sbin/supivpn -learn-address -route-device supivpn0 -route-network 10.203.0.0/24"
   client-disconnect "/usr/sbin/supivpn -route-disconnect -route-device supivpn0 -route-network 10.203.0.0/24"
   ```

3. Copy that reviewed OpenVPN configuration to `openvpn-tcp.conf`, use
   `proto tcp4-server`, `port 443`, a distinct TUN (`supivpn1`) and the TCP
   management socket. Change `-route-device` in both hooks to `supivpn1`.
   Keep the **same** server network, trust material and required metadata gate.
4. Configure routing/firewall policy for both interfaces. Set the controller's
   `profile.tcp_fallback_port`, then restart the node during the maintenance
   window. The packaged node unit starts the optional TCP service when its
   configuration exists. Verify both listeners before distributing new profiles.

Use the actual interface names and VPN network. Do not duplicate existing
`learn-address`, `client-disconnect`, `server`, `dev` or `management` directives.
For Lambda deployments, the public Lambda issues the profile while the same
single agent manages both OpenVPN daemons on the VPN host; Lambda cannot create
the TCP listener, host route or firewall allowance.

Existing **bound UDP-only profiles remain valid** without reissuing their secret
or key. A freshly downloaded profile includes TCP only when configured. Both
connections inherit the same CA, exact server-name verification, tls-crypt-v2 key
and owner-bound proof. Do not use `remote-random` or weaken authentication for
fallback. Unbound profiles are a separate migration; see
[profile ownership](PROFILE_BINDING.md).

Transport fallback establishes a new tunnel and runs authorization again. It
does not transfer a live tunnel, guarantee preservation of its IP address, or
preserve application TCP sessions. TCP-over-TCP can perform poorly under packet
loss, so UDP remains preferred. A rejected/blocked profile or an owner mismatch
must never become an authentication bypass on the other transport.

## Loss of an established UDP tunnel

The endpoint polling timeout does not detect loss of an already established
tunnel. With the packaged `keepalive 10 60`, the client detects silence after
about 60 seconds, while the server waits about 120 seconds before confirming
closure. A fast SAML login on TCP can therefore reach the default one-connection
limit before the old UDP slot is released.

For the **same active profile and verified owner**, a limit caused by a current
opposite-transport grant permits one bounded retry. The controller commits a
`connection_limit_retry` refusal, and the agent acknowledges it as **denied**.
The agent then waits 60 seconds without admitting traffic or reserving an IP.
Heartbeats, other clients, disconnect processing and the original pending-login
deadline continue normally. It finally sends the upstream `AUTH_FAILED,TEMP`
response requesting a fresh attempt on the same endpoint. The delay is enforced
by the agent because clients do not consistently honor TCP retry backoff hints.
No OpenVPN patch or client modification is involved.

The new attempt requires a **new ticket, profile proof and SAML login** and repeats
all current owner, active/blocked, group, validity and cluster-limit checks. The
old session is never evicted, extended or treated as disconnected by a timer in
SupiVPN. Only normal disconnect/cancel or fencing releases its slot. With the
packaged timers, expect roughly two minutes plus browser/network time to recover
from silent loss of an established UDP tunnel; this is not seamless failover.

The database retains the retry budget across controllers, HA nodes, cancellation
and node-generation changes. Another automatic retry for that profile is refused
until five minutes after the retry attempt's original login expiry (at most eight
minutes from registration with the default 180-second login window). A missing or
expired proof, blocked profile, wrong owner, same-transport conflict, another
profile or infrastructure failure does not enable this retry. If the slot is
still occupied on the fresh attempt, the normal connection-limit refusal applies.
If the pending login expires or the node lease is lost during the wait, the
attempt fails closed. Clients that do not handle `AUTH_FAILED,TEMP` need a manual
reconnect after confirmed closure. Never delete login rows or raise limits to
force fallback. See [session accounting](SESSIONS.md).

## Disable TCP again

During a maintenance window, set the controller's `profile.tcp_fallback_port`
to zero, remove the agent's `tcp_management_socket` setting, and move the TCP
OpenVPN configuration out of `/etc/supivpn/node/openvpn-tcp.conf`. Restart the
controller and node, then close the TCP firewall allowance. Existing bound
profiles continue to use their UDP entry. Remove the shared-pool hooks from UDP
only after TCP has stopped; retain the ordinary source-address validation hook.
