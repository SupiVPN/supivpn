# CI scope and documentation checks

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for licensing terms.

`Checks` always reports `Required checks`. Only changes confined to root-level
or `docs/` Markdown can skip executable tests and builds. `COPYRIGHT.md` and
`THIRD_PARTY_NOTICES.md` retain full checks because they affect distribution.
Source, configuration, dependencies, packaging, workflows and tooling always
run the full suite, including when changed alongside documentation.

PRs compare the merge base with their head. Pushes to `main` compare the event's
complete `before` and `after` range, not just the last commit or first parent.
Renames include both paths. Missing commits, invalid IDs, Git errors, empty
diffs, force pushes and unknown contexts fall back to full checks. Release tags,
scheduled scans and manual runs always run everything.

Documentation checks use only Git and Python's standard library: changed-file
whitespace and conflict markers, local Markdown link targets and heading anchors,
release-note structure, repository secret/deployment-pattern audit and language.
No Go SDK, containers or signing/package-tool dependencies are installed for this
path. External URLs are not fetched. The link check covers inline links and
reference definitions in changed Markdown; rendered layout still needs review.

The final gate requires a successful scope and audit. For every executable job it
requires success for code changes and an intentional skip for documentation.
Missing outputs, unexpected skips, failures and cancellations fail the gate.

## CodeQL transition

The advanced [CodeQL workflow](../.github/workflows/codeql.yml) uses the same
scope decision. It retains Actions, Go, JavaScript/TypeScript and Python analysis
with `security-extended`, plus full weekly, manual and release-tag scans. Only
the analysis job can write security events; it has no release credentials or
deployment permissions. CodeQL database upload is disabled; analysis results
still upload to GitHub code scanning. No source paths or queries are excluded.

Activation is a separate repository-setting change. Until it is performed,
GitHub Default setup still runs CodeQL for documentation changes and blocks
uploads from Advanced setup. Do not disable Default setup until the replacement
workflow is reviewed and ready to run.

After approval, switch to Advanced setup, enable the new workflow if GitHub
disabled it, and verify all four analyses and their uploaded results. Check the
existing alert history/configurations for stale results before considering the
switch complete. A failed transition must restore Default setup with the same
languages and extended query suite. No branch protections need to be removed.

See [GitHub's setup instructions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).
