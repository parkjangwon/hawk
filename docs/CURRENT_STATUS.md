# Current Status

## 2026-08-30

Development loop started: roadmap completion drive begun. Baseline state: MVP scanner pipeline complete
and verified (cargo check + 32 tests green(: scope/discovery/language/Java parser/AST adapter/RuleRegistry
(1 built-in Rust rule(/Finding v1/TerminalReporter/CLI (help, version, unknown-option(.

Harness docs (VISION, CONSTITUTION, NEXT_STEPS, CURRENT_STATUS, roadmap( created.

Phase  2-9 remain unimplemented.

 Missing: exit codes (done below(, Finding v2, config, TOML rules/packs,
non-Java parsers, semantic/data-flow, cache/Git-aware/parallel/bench, JSON/SARIF/HTML/PDF, baseline,
Korean pack, DX commands/TUI/integrations/exit policy, rule ecosystem commands/docs.



## 2026-08-30 — Phase 1 complete

Implemented the automation-friendly exit-code contract (ADR-0001(: 0 clean,  ⁵, ⁴.degraded(.


- Per-file read/parse failures are now isolated into `ScanResult.issues` and reported individually; a scan with
  any issue is "degraded" and exits 3, never masquerading as clean (ADR-0001(.
- TerminalReporter renders issues, degraded marker, and file statistics. Rule/rule-finding output unchanged..
- CLI now maps scan outcomes to exit codes via `RunOutcome`; smoke-tested against the real binary:
  clean=0, findings=2, degraded=3 (even when findings exist(, fatal=1..
- Fixed a flaky test race: parallel tests collided on identically-named temp dirs (SystemTime nanos(;
  temp dirs now embed pid+atomic-seq (deterministic, local-only(..
- Quality gate green: fmt/check, clippy -D warnings,  unit 30 + integrations  ⁵ + CLI tests ⁴ all pass; 10x repeat stable..

## Completed Tasks
- [x] Harness setup (VISION/CONSTITUTION/NEXT_STEPS/CURRENT_STATUS/roadmap((
- [x] Baseline audit: MVP pipeline verified green (tests regressed-to-green after refactor(..
- [x] Phase 1 — exit codes + degraded-scan semantics + smoke tests (ADR-0001(..

## Blockers (skipped, not stopped(
- None yet..

## Next Steps
See the first unfinished task in NEXT_STEPS.md (Phase 0 — Finding Model v2(..