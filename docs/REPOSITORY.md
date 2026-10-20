# Repository workflow

The canonical repository is [SupiVPN/supivpn](https://github.com/SupiVPN/supivpn).

Clone it for read-only development, or fork it to contribute:

```bash
git clone https://github.com/SupiVPN/supivpn.git
cd supivpn
git switch -c fix/short-description
```

Set your own Git name and email locally. GitHub's account-specific noreply
address is suitable if you do not want your email in commit metadata.
Run the relevant checks from [BUILD.md](../BUILD.md), commit your change, push
your working branch to your fork, and open a pull request against `main`.

Explain the problem, resulting behavior, tests and compatibility impact.
Security-sensitive changes need focused regression tests. Use
[private vulnerability reporting](../SECURITY.md) for undisclosed vulnerabilities.

Pull requests and main commits run [Checks](../ci/README.md). Documentation-only
pull requests run the source and tooling audit; code changes run native ARM64
and AMD64 checks. Maintainers publish releases using signed tags and reviewed
GitHub Actions outputs. See [release delivery](RELEASES.md).
