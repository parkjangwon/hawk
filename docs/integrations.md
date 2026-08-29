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