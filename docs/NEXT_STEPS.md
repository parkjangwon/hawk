# Next Steps

Prioritized task queue for the development loop, derived from ROADMAP.md.
Only checked when the implementation, tests, documentation, and verification
(cargo fmt/clippy/test, git diff --check( are complete.

## Task List (by priority)

- [x] **Phase 1 — Exit codes & CLI tests**: exit-code contract (0 clean, 1 fatal,  ⁴.degraded(,
      wired through main, unit+integration tests. Smoke-tested against the real binary: clean=0,
      findings=2, degraded=3, fatal=1. Flaky temp-dir race in parallel tests fixed (pid+seq suffix(.
- [ ] **Phase 0 — Finding Model v2**: add confidence, language, framework, cwe, owasp, category,
      recommendation, code_snippet, fingerprint( to the normalized Finding Model; stable fingerprint
      algorithm+deterministic ordering+ tests.

- [ ] **Phase 2 — Design ADRs**: config filename `hawk.toml`, data dir `.hawk/`, rule DSL schema, signature/capability model(
- [ ] **Phase 2 — Config module**: `hawk.toml` (include/exclude, rule pack selection, report options, policy(;
      CLI overrides; precedence Defaults → Project Config → CLI.

- [ ] **Phase 2 — Rule DSL & engine**: TOML rules (pattern(regex(, tree-sitter query(; registry loads
      built-in pack embedded, custom packs from config dirs; engine executes data-driven rules..
- [ ] **Phase 2 — Built-in packs**: Java security pack (runtime-exec, process-builder, hardcoded-secret,
      cookie/println, sql-concatenation, etc; migration of hardcoded Rust rule into pack(; pack manifest+versioning..
- [ ] **Phase 2 — User Rule Packs**: `--pack`, `--pack-dir`, selection in config; resolution precedence; tests..
- [ ] **Phase 2 — `hawk rule test`**: run a rule file against fixture source, assert expected findings; playground command..
- [ ] **Phase 3 — Parser matrix**: JavaScript/TypeScript/Python/Go tree-sitter grammars wired into ParserRegistry,
      language detection already complete; per-language tests..
- [ ] **Phase 3 — New-language basic rules**: eval/innerHTML/child_process (JS/TS(; os.system/subprocess/pickle (Python(;
      exec.Command (Go(; fixture tests..
- [ ] **Phase 3 — Semantic module**: symbol collection (classes, methods, variables, types( + usage analysis
      (declared/assigned/read(; tests; exposed for data-flow phase..
- [ ] **Phase 4 — Data-flow engine**: intraprocedural taint: sources, sanitizers, sinks from rule DSL;
      gen/kill/propagate; deterministic. Tests with hand-built graphs..
- [ ] **Phase 4 — Data-flow rules**: SQL injection, command injection, XSS, path traversal, SSRF,
      security-sensitive API; Java-first; fixtures vulnerable+safe for each..
- [ ] **Phase 5 — Incremental cache**: file hashing (blake3(, per-file result cache (.hawk/cache(, cache-key includes
      hawk version/rule pack versions; incremental reuse; tests..
- [ ] **Phase 5 — Git-aware**: `hawk --changed`, `hawk --staged`; pre-commit hook sample; tests..
- [ ] **Phase 5 — Parallel & fast**: rayon parallel file analysis with deterministic reassembly; benchmark suite (criterion(
      + performance budget doc..
- [ ] **Phase 6 — Machine reports**: JSON and SARIF 2.1.0 output (schema-tested(..
- [ ] **Phase 6 — Human reports**: HTML security assessment report (self-contained(,, PDF (pure-Rust writer(; snippets+
      remediation+mappings in reports; report metadata (duration, timestamp, versions, stats, severity summary(..
- [ ] **Phase 6 — Baseline**: create/update, stable fingerprints, suppression, new/fixed/regression detection; tests..
- [ ] **Phase 7 — Korean secure-coding pack**: research KISA secure-coding guidance surfaces, licensing/attribution,
      independent Hawk rule IDs mapped to Korean guidance + CWE/OWASP; high-value Java rules first; pack docs+fixture tests..
- [ ] **Phase 8 — Rule DX commands**: `hawk rule list`, `hawk rule explain <id>`; `hawk config` (effective config(; source
      highlighting in snippets; helpful error hints..
- [ ] **Phase 8 — TUI**: minimal keyboard-navigable findings/config inspector (`hawk tui`(..
- [ ] **Phase 8 — Integration & CI**: GitHub Actions workflow, VS Code/IntelliJ guides+configs, CI-friendly exit policy
      (`exit-on-severity` config+flag(..
- [ ] **Phase 9 — Rule ecosystem**: pack/rule conventions docs, `hawk rule validate`, compatibility metadata+validation,
      contribution guide, company/private pack docs, distribution notes..
- [ ] **Final — Roadmap reconciliation**: tick all ROADMAP.md boxes (or document external blocks(,, README status,
      final quality gates green, final journal entry..