# AGENTS.md

Guidelines for AI agents (GitHub Copilot, Devin, etc.) contributing to this repo.

## Repository purpose

This is a GitHub Action that captures e2e / regression test traffic as a
TLS-decryptable PCAP bundle. It uses mitmproxy as a forward proxy for TLS
interception and tcpdump (Linux) / netsh trace (Windows) for raw packet capture.

The action is split into two parts:
- `start/` (composite) — installs mitmproxy, starts capture with inline filter addon
- `stop/` (node20) — stops capture, bundles artifacts; S3 upload runs as a post step

## Commit messages — Conventional Commits

All commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <subject>

<optional body — lines <= 100 chars>
```

**Allowed types:** `build` `chore` `ci` `docs` `feat` `fix` `perf`
`refactor` `revert` `style` `test`

**Rules enforced by commitlint (CI) and the local pre-commit hook:**
- `subject-empty` — subject must not be empty
- `type-empty` — type must be present
- `body-max-line-length` — body lines must not exceed 100 characters
- Trailers like `Co-authored-by:` are exempt from the line-length rule

**Local hook setup** (one-time, per clone):
```bash
git config core.hooksPath .githooks
```

Do **not** include `Agent-Logs-Url:` or other long auto-generated trailers
in commit bodies; they will exceed the 100-char body line limit.

## Release workflow

A release is triggered by bumping `VERSION` (strict semver `X.Y.Z`) on `main`.
Every PR must include a `VERSION` bump — the `version-bump` CI job enforces this.

## File layout

| Path | Purpose |
|------|---------|
| `start/action.yml` | Composite action: install mitmproxy, start capture |
| `stop/action.yml` | Node20 action: stop capture, bundle, S3 upload (post step) |
| `stop/src/main.js` | Stop capture + bundle logic |
| `stop/src/post.js` | S3 upload (runs at job cleanup time) |
| `scripts/filter-addon.py` | mitmproxy inline filter addon |
| `VERSION` | Strict semver version string |
| `.github/workflows/test.yml` | Integration test (MinIO + PCAP verification) |
| `.github/workflows/commitlint.yml` | Commit message validation |
| `.githooks/commit-msg` | Local commitlint hook |

## What agents should not do

- Do not add `Agent-Logs-Url:` lines to commit bodies
- Do not bypass `git config core.hooksPath .githooks`
- Do not hardcode AWS credentials; rely on environment / OIDC
- Do not remove the integration test; it validates the full capture pipeline
- Do not move filtering out of the addon into a post-processing step
