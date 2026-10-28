# SupiVPN runtime

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

This Go module contains the agent, SAML controller, PostgreSQL backend, migrator,
profile issuance, and VM/AWS adapters. OpenVPN Community 2.7.8 runs separately
and communicates with the agent through a management Unix socket.

## Entry points

| Command | Build output | Purpose |
| --- | --- | --- |
| `./cmd/supivpn` | `local/arm64/supivpn` | OpenVPN agent, including learn-address mode |
| `./cmd/supivpn-controller` | `local/arm64/supivpn-controller` | VM controller |
| `./cmd/supivpn-lambda` | `local/arm64/bootstrap` | Public AWS Lambda |
| `./cmd/supivpn-agent-lambda` | `local/arm64/bootstrap-agent` | Agent API Lambda |
| `./cmd/supivpn-recovery-lambda` | `local/arm64/bootstrap-recovery` | Recovery/operator Lambda |
| `./cmd/supivpn-migrate` | `local/arm64/supivpn-migrate` | PostgreSQL migrations |
| `./cmd/supivpn-profile` | `local/arm64/supivpn-profile` | Key bootstrap and local profile issuance |
| `./cmd/supivpn-package` | `local/arm64/supivpn-lambda.zip` | Lambda artifact packaging |

## Configuration

- [config.example.json](../examples/config.example.json): node agent with a local controller socket.
- [server.conf.example](../examples/server.conf.example): OpenVPN fixture without production routing.
- [controller.vm.example.json](../examples/controller.vm.example.json): VM controller.
- [controller.lambda.example.json](../examples/controller.lambda.example.json): public AWS controller.
- [agent.lambda.example.json](../examples/agent.lambda.example.json): agent API Lambda.
- [recovery.lambda.example.json](../examples/recovery.lambda.example.json): recovery Lambda.
- [Lambda isolation](LAMBDA_ISOLATION.md): separate IAM/DB privileges, configuration and cutover.
- [client.ovpn.example](../examples/client.ovpn.example): template; complete profiles need their own tls-crypt-v2 key.

Deployment replaces example addresses, groups, node IDs, and paths.
A cluster needs a shared controller/PostgreSQL and disjoint node pools.
In remote mode, the controller handles SAML and the agent applies verified
decisions; its local HTTPS listener serves health/readiness.

`vpn_login_confirmation` defaults to enabled when omitted, null, or true.
Set it on the public controller (VM/Lambda);
omit it from remote nodes and agent-only/recovery Lambdas. Setting it to false
skips the pre-SAML page and reintroduces the risk of a relayed login link using
another person's IdP session to authorize the requesting VPN client. Profile
downloads are unaffected. See the [JSON example and security limits](IDENTITY_PROVIDER.md#vpn-login-confirmation).

`pending_seconds` sets the browser authorization timeout; `session_seconds`
sets VPN authorization duration. The example 180/43200 seconds is not mandatory
policy for every deployment. Groups can override `session_seconds` (60..43200,
or explicit 0 for no local limit); omitted/null group values inherit the default.
A signed IdP `SessionNotOnOrAfter` also limits 0. Expiry closes the tunnel;
the client reconnects and performs a new SAML login. There is no renewal.
Without a local or IdP deadline, access can survive user/group/MFA changes
indefinitely; configuring 0 emits a startup warning.

The default simultaneous connection limit is one per user, with group overrides.
See [sessions, heartbeat, and confirmed fencing](SESSIONS.md).

## Tunnel logs

After verified SAML login, the agent includes the exact NameID as `username`:

```json
{"timestamp":"2026-10-15T12:00:00Z","level":"INFO","message":"VPN tunnel established","schema_version":1,"service":"supivpn","component":"agent","event":"vpn.tunnel_established","cid":12,"kid":0,"username":"alice","group_name":"admins-vpn","address":"10.200.0.129"}
```

Quotes and control characters are escaped in JSON; username never comes from
the profile or OpenVPN peer info. It is empty for old grants or NameIDs over
1024 bytes. Disconnects before authorization log only the CID. Logs contain personal data.
Current controllers require [database schema 12](POSTGRES.md) and bound profiles.
Follow the [upgrade order](PROFILE_BINDING.md) before updating agents.
The `username` field is sent only for an allowed
`fetch` decision with `include_username=true`.
New agents are incompatible with old controllers that do not recognize that parameter.
Before SAML, OpenVPN sees the opaque profile ID, not the verified user's name.
Profiles carry an opaque ID and secret; never collect raw management credentials.

VM services now default to rotating JSON files; Lambda and CLI commands use
stderr. See [logging destinations, retention and collection](LOGGING.md)
before deploying or updating text-based log filters.

## Manual checks and builds

Quick commands from the project root: `make build`, `make test`, `make vet`,
`make integration`, and `make security`.
See [BUILD.md](../BUILD.md) for individual components and the full suite.

Run the following commands from the repository root.
[go.mod](../go.mod) specifies Go and dependency versions.
Set custom `GOPATH`/`GOCACHE` as needed.

```bash
go test -race -count=1 -timeout=180s ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn ./cmd/supivpn
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-profile ./cmd/supivpn-profile
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-migrate ./cmd/supivpn-migrate
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-controller ./cmd/supivpn-controller
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -tags lambda.norpc -o local/arm64/bootstrap ./cmd/supivpn-lambda
```

The Lambda packager defaults to an ELF ARM64 bootstrap. Use `-arch amd64` with
explicit `-binary` and `-output` paths for AMD64. The default ZIP contains
the executable and profile template; deployment supplies metadata, for example
through a Lambda layer:

```bash
go run ./cmd/supivpn-package
```

To include metadata in the ZIP, run
`go run ./cmd/supivpn-package -metadata /path/to/idp-metadata.xml`
and use controller path `/var/task/idp-metadata.xml`.
A layer's contents determine its path, for example `/opt/idp-metadata.xml`.
The ZIP contains no private keys.
To check your public metadata separately, specify its actual deployment path:

```bash
SUPIVPN_TEST_IDP_METADATA=/path/to/idp-metadata.xml go test -race -run '^TestLocalIDPMetadata' ./internal/agent
```
Without this variable, the metadata test is skipped. The rest of the unit suite
needs no live IdP or database. PostgreSQL tests use the `integration` build tag:
[instructions](POSTGRES.md#running-integration-tests).
[Native OpenVPN tests](../testdata/openvpn/README.md) separately check a real tunnel.

## SAML, groups, and profiles

The controller verifies the signed assertion, InResponseTo, browser binding,
audience, validity periods, and replay protection. Group names match exactly.
Priority selects one group; the agent assigns its IP.
See [IdP setup](IDENTITY_PROVIDER.md) and [API](CONTROLLER_API.md).

`tls-crypt-v2` admits a client to TLS/SAML but does not authorize the user.
Profiles contain a secret and must be stored/transferred as private files.
See [keys](TLS_CRYPT_V2.md) and [HTTPS download](PROFILES.md).

Issued bound profiles verify the CA, validity period and exact VPN server name.
Optional [UDP/TCP fallback](TRANSPORTS.md) retains these checks for both endpoints.
[SECURITY.md](SECURITY.md) describes security and dependency checks.
