# SupiVPN controller

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The controller runs as a VM service or AWS Lambda. It verifies SAML, selects one
VPN group, stores one-time state in PostgreSQL, and issues an agent decision or
client profile. The node agent allocates the IP address.

## Startup

| Mode | Entry point | Configuration |
| --- | --- | --- |
| VM | `cmd/supivpn-controller` | [controller.vm.example.json](../examples/controller.vm.example.json) |
| AWS Lambda | `cmd/supivpn-lambda` | [controller.lambda.example.json](../examples/controller.lambda.example.json) |

Replace every example hostname, account/instance ID, and group.
Public URLs, SAML policy, metadata, and database settings must agree across replicas.
See [parameters, API, and agent authentication](CONTROLLER_API.md).
Optional [assertion encryption](ASSERTION_ENCRYPTION.md) uses a dedicated
controller key and explicit disabled/optional/required modes.
[VPN login confirmation](IDENTITY_PROVIDER.md#vpn-login-confirmation) is enabled
by default; `vpn_login_confirmation=false` explicitly disables it and restores
the documented risk from relayed login links. Set this only on the public controller.

The VM process opens HTTPS and a private agent Unix socket with peer UID checks.
It can run next to OpenVPN but does not own its management socket.
The deployment supplies TLS cert/key/chain and restarts the relevant service
after updates according to its lifecycle rules.

Lambda receives API Gateway events, private database access, and minimal IAM
permissions. REST proxy and HTTP API payload 2.0 are supported; event format,
API ID, stage, domains, and routes must match adapter configuration.
Agents do not need a Function URL or direct Lambda invocation.

## HTTPS and protection

Public routes cover health, metadata, login initiation, ACS, and profile download.
Expose both `GET` and `POST <public_url>/login/{ticket}`. With the default login
confirmation enabled, GET displays the page and only the browser-bound same-origin
form submission starts SAML. When explicitly disabled, GET redirects straight to
the IdP. Preserve Origin, cookies and form bodies through proxies so the default
can be restored without changing routes.
For a single SAML dashboard tile, also expose exact `POST <public_url>/saml/launch`.
It only redirects to the existing profile login; unsolicited assertions grant
no access. See [Okta setup and rollout requirements](PROFILES.md).
Internal `POST /agent/v1/*` routes have separate authentication and access rules.
AWS uses AWS_IAM and exact STS session ARN-to-node ID matching.

Public HTTPS can pass through Cloudflare or another reverse proxy.
DNS zones, plans, rulesets, origin restrictions, rate limits, and connection
limits belong to the deployment. Hostnames alone are insufficient:
direct origin access must not bypass the access policy.
Also limit Lambda concurrency and API request rates.

Disable caching and body tracing on SAML/profile endpoints.
Never log assertions, cookies, tickets, credentials, or profile contents.
The UDP OpenVPN endpoint is separate from the HTTP proxy.

Browser pages use the SupiVPN website palette, system fonts and a small embedded
stylesheet. They load no scripts, external fonts, images or analytics. The CSP
allows only the exact stylesheet hash; preserve this header and do not inject or
rewrite styles at the proxy. Confirmation keeps its restricted form destination
and CSRF checks. Browser success/error pages require an explicit `Accept:
text/html`; other clients retain text responses and the same HTTP status codes.
Profile downloads remain attachments. A successful browser sign-in does not
claim that a VPN tunnel is connected; the client confirms that separately.

## Build and review

Run these commands from the repository root:

```bash
go test -race -count=1 -timeout=180s ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-controller ./cmd/supivpn-controller
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -tags lambda.norpc -o local/arm64/bootstrap ./cmd/supivpn-lambda
go run ./cmd/supivpn-package
```

By default, the packager expects `local/arm64/bootstrap` and `examples/client.ovpn.example`.
It creates `local/arm64/supivpn-lambda.zip` with the executable and profile template.
Metadata is supplied by the deployment; the optional `-metadata` argument can
include public IdP metadata in the archive. Private keys, database passwords,
and DSNs are not packaged. Packager parameters can override local paths.

For commercial distribution, include the licensing materials described in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); the development ZIP is not
a complete release bundle. Artifact storage and delivery are separate choices.

## Deployment and checks

Prepare the database and apply migrations before starting the controller.
Supply metadata, configuration, and required secrets. Profile download needs
read access to the same wrapping key used by VPN nodes, without permission
to create or rotate it.

Check health, unauthorized-agent rejection, signed agent requests, SAML login,
group priority, rejection without a group, replay protection, and profile download.
After node replacement, update verified identity mappings before accepting clients.
Cloud deployment checks are not part of the Go unit suite.
