# Local operator CLI

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for licensing terms.

**Unreleased:** `supivpn-cli` is a separate Debian package for the next minor
series (0.8). The `supivpn` metapackage installs it with exactly matching node
and controller versions. Existing 0.6/0.7 release assets remain unchanged.

The first version supports a **combined Debian host** with the node, upstream
OpenVPN, controller and systemd installed locally. PostgreSQL may be on another
host with the existing verified TLS configuration. Lambda and split
node/controller deployments are not supported by this CLI.

## Inspect before changing

Run commands over your normal trusted SSH/console session with `sudo`.
Output is bounded JSON suitable for terminal inspection or automation.

```sh
sudo supivpn-cli status
sudo supivpn-cli status --instance bound
sudo supivpn-cli profiles list --limit 50
sudo supivpn-cli profiles list --limit 50 --after svp1_0123456789abcdef0123456789abcdef
sudo supivpn-cli profiles status svp1_0123456789abcdef0123456789abcdef
```

`status` reports systemd load/active/substate for the controller and the selected
agent/OpenVPN pair; it is **not** an end-to-end VPN or IdP health check. The
default pair is `supivpn-node`/`supivpn-openvpn`. `--instance bound` selects
the second pair used during [profile migration](PROFILE_BINDING.md).

Profile listing returns at most 100 rows, ordered by opaque profile ID, and a
`next_cursor` when another page exists. Use that value with `--after`; this
is not a time-ordered or snapshot-consistent inventory. Profile responses contain
only ID, active/blocked state, revision and creation time. Identify the relevant
ID through the protected `vpn.tunnel_established` logs; there is no plaintext
owner, owner hash, proof or secret digest in CLI output.

## Block and reactivate a profile

Read status, inspect the profile ID, then use the returned revision:

```sh
sudo supivpn-cli profiles block svp1_0123456789abcdef0123456789abcdef --revision 1 --yes
sudo supivpn-cli profiles status svp1_0123456789abcdef0123456789abcdef
sudo supivpn-cli profiles activate svp1_0123456789abcdef0123456789abcdef --revision 2 --yes
```

`--yes` is required for mutations. A stale revision fails without overwriting
a newer decision. After a timeout or failed response, the mutation may already
have committed: inspect status before retrying. Reactivation permits a **new**
SAML login; it does not revive a previous tunnel. Use the revision actually
returned by your installation, not the illustrative numbers above.

Blocking prevents future admission using that profile, including the checked
SAML decision/fetch/ack stages. It is **not a user ban**, does not prevent the
same authorized user from downloading a new profile, and does not terminate an
already established tunnel. An authorization already applied before the block
is an existing session; blocking is not an atomic disconnect operation.

If a block races with an authorization already applied but not yet acknowledged,
the agent can stop the entire listener under its existing fail-closed
acknowledgement rule. Other tunnels on that listener may disconnect as a result.
Keep independent administrative access when performing urgent revocation.

## Inspect or terminate current user sessions

```sh
sudo supivpn-cli sessions status --user alice
sudo supivpn-cli sessions drop --user alice --yes
sudo supivpn-cli sessions status --user alice
sudo supivpn-cli sessions drop --user alice --instance bound --yes
sudo supivpn-cli sessions status --user alice --instance bound
```

Supply the exact case-sensitive SAML NameID. The agent scopes it to its configured
IdP issuer. A drop affects all of that user's matched sessions on the **selected
local listener**, potentially more than the blocked profile. It is a one-time
termination request, not a reconnect ban. `requested` or `closing` is not proof
of closure: poll until `matched=0` and `unidentified=0`. Unreachable listeners,
unidentified sessions or timeouts mean the result is unconfirmed. Repeat on
every relevant listener/node; there is no automatic cluster traversal.

For urgent account revocation, block IdP access before terminating sessions.
See [revocation](REVOCATION.md) for in-flight logins, legacy sessions and the
30-second kill-confirmation guard, which can stop the entire pair if OpenVPN
does not confirm closure. Maintain independent administrative access before
dropping your own VPN session.

## Security boundaries

- Requires real and effective UID 0; no setuid binary, sudoers rule, socket group,
  network listener, new daemon or remote target is installed.
- Fixed installed paths and a matching local Unix-connected node/controller are
  required. Caller-selected config files, database URLs, arbitrary commands and
  SQL are not accepted. Instance names are bounded and cannot contain paths.
- Root-owned files/directories must not be writable by other users; symlinks are
  refused. `database.env` must remain root-only (0600).
- Database operations run as `supivpn-controller` in a bounded transient systemd
  service with no capabilities, no new privileges, read-only system files and
  private devices. systemd reads the existing credential file internally.
  CLI neither reads/copies that secret nor places it in argv.
- Child processes have fixed executable paths and a minimal environment; caller
  PATH, pager, D-Bus, loader and PostgreSQL overrides are not inherited. There is
  no shell evaluation. Requests use stdin, output is bounded and re-encoded from
  allowlisted fields; raw subprocess/database errors are not displayed.
- Session operations reuse the agent's root-only Unix socket and peer-UID check.
  No new permissions are granted to the public controller or Lambda roles.
- The local administrator, systemd manager, root-owned configuration and the
  combined controller's existing DB role are trusted. This CLI is not a security
  boundary against root or a compromised controller. It is not an immutable audit
  ledger; retain command receipts and protected system/session logs as needed.
- Commands never silently run migrations, rewrite configuration, restart
  services, install packages or retry mutations.

## Lambda: temporary database procedure

Use [the bounded SQL procedure](LAMBDA_PROFILE_ADMIN.md). Installing this CLI on
a laptop or Lambda host is not a supported way to administer cloud deployments.
A dedicated remote administration interface is deferred.
