# Hawk editor integration

Hawk is a CLI tool, so editors integrate with it through task runners and
problem matchers rather than a plugin.

## Visual Studio Code

Add a task in `.vscode/tasks.json` that scans the workspace and marks issues:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Hawk: scan",
      "type": "shell",
      "command": "hawk --format json .",
      "problemMatcher": {
        "owner": "hawk",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": {
          "regexp": ".*\"file\": \"(.*)\",.*\"line\": ([0-9]+).*",
          "file": 1,
          "line": 2
        }
      },
      "group": "build"
    }
  ]
}
```

## IntelliJ IDEA

- Use **Tools → Shell Scripts → Run** with `hawk —format json .` and a custom
  JSON problem matcher, or wire it into a file watcher:
  - Settings → Tools → File Watchers → `+` → Custom
  - Program: `hawk`
  - Arguments: `--format json $FilePath$`

## pre-commit

Copies of `scripts/pre-commit.example`:

```bash
cp scripts/pre-commit.example .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Pre-commit scans staged files and aborts when findings exceed the configured
threshold.

## Exit codes (for CI/editor automation)

| Code | Meaning |
|------|---------|
| 0    | Clean (no findings at/above threshold) |
| 1    | Fatal: configuration/option/path error |
| 2    | Findings at/above `--fail-on-severity` (default: any) |
| 3    | Degraded: some files could not be analyzed; results incomplete |
---

## CI/CD pipeline

The repository ships four GitHub Actions workflows (`.github/workflows/`):

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push to `main`, PR | Quality gates on **ubuntu/macos/windows**: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --all-features`, `git diff --check`, plus a fixture-coverage job that fails when a built-in rule lacks a passing `ruleid:`/`ok:` fixture |
| `scan.yml` | push, PR | **Self-scan**: Hawk analyzes its own repository with `--format sarif`; findings at/above `exit-on-severity` fail the pipeline, and the SARIF artifact is always uploaded |
| `audit.yml` | push to `main`, PR, weekly | Dependency vulnerability audit via `cargo audit` (RustSec advisory DB) |
| `release.yml` | tag `v*` | **Continuous delivery**: builds `hawk` for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64) and attaches the binaries to a GitHub Release |

### Releasing

```bash
git tag v0.2.0
git push origin v0.2.0
```

The tag triggers `release.yml`, which publishes `hawk-<target>.tar.gz`/`.zip`
assets on the matching GitHub Release. Pre-release tags (`v0.2.0-rc.1`) create a
pre-release.

### Self-scan configuration

`hawk.toml` at the repository root drives the self-scan: it excludes the
intentional vulnerability fixtures under `*/fixtures/` and enforces the CI
severity policy. Adding a new rule without a fixture fails `ci.yml` — see
`docs/rules-ecosystem.md` for the fixture format.
