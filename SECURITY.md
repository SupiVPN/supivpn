# Reporting a vulnerability

Please do not disclose an exploitable authentication, authorization, cryptography
or infrastructure issue in a public issue or pull request.

Use **Security -> Advisories -> Report a vulnerability** in
[SupiVPN/supivpn](https://github.com/SupiVPN/supivpn/security/advisories/new).
If private vulnerability reporting is unavailable, contact the maintainer at
`security@supivpn.com` and arrange a private channel before sending sensitive details.
Do not send production tokens, assertions, keys, credentials or personal data.

Include the affected version, prerequisites, a minimal synthetic reproducer,
expected behavior and impact. We will coordinate assessment and disclosure;
there is currently no guaranteed response SLA or paid bug bounty.

The latest release is the primary target for fixes. No long-term support branch
is promised. Open limitations, trust boundaries and mitigations are documented
in [the security model](docs/SECURITY_MODEL.md),
[the review record](docs/SECURITY_REVIEW.md) and
[dependency verification](docs/SECURITY.md). Automated tests and scans are not an
independent security audit or a claim that the service is free of vulnerabilities.
