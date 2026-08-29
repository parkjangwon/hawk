# ADR-0003: Project configuration (`hawk.toml`) and local data directory (`.hawk/`)

## Status

Accepted

## Context

ROADMAP Phase 2 introduces a human-editable project configuration file. README leaves the filename
open ("securelint.toml" was a placeholder) and requires a zero-configuration first run, with precedence
Defaults → Project Config → CLI Arguments. A local data directory is also needed for baseline/cache/report
artifacts (Phase 5/6), and the README sketches `.securelint/`.

## Decision

**Config filename: `hawk.toml`** in the project root (the directory from which Hawk is invoked, or the
nearest ancestor containing the file). Rationale: the tool is named Hawk; discovery-by-nearest-ancestor
keeps it useful in subdirectories of a project. The file is optional — `hawk .` works without it.

**Local data directory: `.hawk/`** in the project root, used for `baseline.json`, `cache/`, and `reports/`
in later phases. The name matches the binary/config identity and is conventionally hidden. It must never
be treated as source, and it carries no config state.

**Naming style.** Options use `kebab-case` inside TOML (TOML convention) and `--kebab-case` on the CLI;
the CLI flag that maps to config is the same word. CLI arguments take precedence over config (Defaults →
Project Config → CLI).

**Location resolution.** Configuration search: current working directory → ancestors upward. The first
`hawk.toml` found wins. CLI `--config <path>` forces a specific file.

## Consequences

- Zero-config workflows keep working: no file, clean defaults.
- A single conventional filename (`hawk.toml`) is easy to explore, document, and validate.
- `.hawk/` stays out of the user's way and can be git-ignored (`# .hawk/`).
- Naming contract becomes compatibility-sensitive once released (see README backward-compat policy).