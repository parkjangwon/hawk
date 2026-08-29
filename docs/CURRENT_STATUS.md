# Current Status

## 2026-08-30 — Roadmap completion drive

Started with an MVP scanner (scope/discovery/Java parser/1 built-in rule/terminal
reporter) and a comprehensive ROADMAP. All Phases (0–9) are now implemented and
the quality gates are green on the default branch.

### What shipped (by area)

- **Engine:** tree-sitter parsers for Java/JS/TS/Python/Go; AST adapter;
  pattern rules (regex + `not-regex` + `fix`); tree-sitter **query** capability;
  intraprocedural **taint** engine with source→sanitizer→sink w/best-effort
  propagation.
- **Packs:** embedded packs for `java`, `javascript`, `python`, `go`, and
  `korea-secure-coding`; pack manifest + versioning + duplicate/severity
  validation; `--pack` selection; pack-dir loading for custom packs.
- **Config:** `hawk.toml` (include/exclude/packs/pack-dirs/report/policy),
  discovered upward; `--format`, `--output`, `--fail-on-severity`, `--changed`,
  `--staged`, `--no-cache`.
- **Scanner quality:** parallel (rayon) with deterministic reassembly; file-hash
  incremental cache; explicit degraded-scan semantics; exit codes 0/1/2/3.
- **Reports:** terminal, JSON (metadata + severity summary), SARIF 2.1.0, HTML
  (snippets); English-first.
- **Baseline:** `hawk baseline create|status` with stable fingerprints and
  new/existing/fixed classification.
- **DX / ecosystem:** `hawk rule list|explain|test|validate`, `hawk config`,
  Semgrep-style `ruleid:`/`ok:` fixture testing, CI workflows, editor/pre-commit
  integration docs, contributing + rule-ecosystem docs, benchmark example.

### Quality gates

`cargo fmt`/`clippy -D warnings`/`test --all-features`/`git diff --check` all
green; 80+ unit/integration tests.

### Remaining (documented, low-priority)

Standalone TUI, PDF output, independently published Korean pack,
framework-specific rules, dedicated AST cache, git-aware baseline,
criterion-scale CI benchmarks, optional pack distribution mechanism.

## Completed Tasks

- [x] Harness setup (VISION/CONSTITUTION/NEXT_STEPS/CURRENT_STATUS/roadmap)
- [x] Phase 0–9 implementation and verification
- [x] Semgrep-inspired tooling (fixtures, not-regex/fix, query capability)

## Blockers (skipped, not stopped)

- None. (Items left unchecked in ROADMAP are deliberate scope decisions, not
  blockers.)