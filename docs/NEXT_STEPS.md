# Next Steps

Task queue for the development loop, derived from ROADMAP.md.
All **Phases 0–9 have been implemented and verified** (quality gates green).
Remaining items are known future work documented in ROADMAP.md's unchecked
boxes — each is a deliberate non-blocker (external/credentialed, deep
performance work, or low-value-for-scope additions).

## Deliberate future work (not blocked)

- Framework-aware rules (Spring/React/Django/etc.) — extension via packs.
- Dedicated AST cache and git-aware baseline — current file-hash cache and
  standalone baseline cover the workflows.
- Independently published Korean rule pack and standards-licensing review.
- Standalone TUI and PDF rendering — CLI-first interactions remain the norm.
- Wide performance budgets in CI; currently provided by `examples/scan_bench`.
- Optional distribution mechanism + SQLite history (explicitly non-goals).

## Completed (summary)

- Phases 0–9 implemented: engine, parsers, taint, packs, cache, git-aware,
  parallel, reports (JSON/SARIF/HTML), baseline, Korean pack, DX commands,
  CI/editor docs, rule ecosystem.
- Semgrep-inspired: `ruleid:`/`ok:` fixture annotations, `not-regex` + `fix`,
  tree-sitter query capability.