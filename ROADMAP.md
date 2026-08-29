# Hawk Roadmap 🦅

This roadmap records the current agreed direction for Hawk. It is intentionally implementation-oriented so future coding agents can use it as project context without relying on chat history.

## Phase 0 — Architecture & Design

**Status: Active**

The architecture is being implemented incrementally. Open design decisions below must be resolved before the corresponding public contract is frozen. Do not block small, isolated implementation work unnecessarily.

Before substantial implementation of each public subsystem, settle the following interfaces:

- [ ] Define final architecture and crate/module boundaries.
- [x] Define the normalized Finding Model.
- [x] Define the Report Model.
- [x] Define the Rule DSL / TOML schema.
- [x] Define Rule Pack manifest and versioning.
- [x] Define configuration schema and final config filename.
- [x] Define severity and confidence semantics.
- [x] Define finding fingerprint/stability rules.
- [x] Define baseline behavior.
- [x] Define include/exclude/ignore semantics.
- [x] Decide parser technology and language-specific AST adapters.
- [ ] Decide licensing and attribution requirements for external rule standards.
- [ ] Document which Korean secure-coding standards/rules can be implemented and how they are attributed.
- [x] Keep optional future storage extensibility in mind without introducing a database.

### Guiding architecture

```text
CLI / TUI
    ↓
Config
    ↓
Scope / File Discovery
    ↓
Parser / AST
    ↓
Semantic / Data Flow
    ↓
Rule Engine ← Rule Packs
    ↓
Finding Model
    ↓
Report / Output
```

### Engineering constraints

- TDD is mandatory for new behavior where practical.
- Keep CLI, core analysis, rules, findings, and reporting independently testable.
- Prefer small vertical slices over large rewrites.
- Every security rule needs deterministic vulnerable/safe fixtures.
- Preserve deterministic discovery, finding ordering, and fingerprints.
- Parser/config/rule failures must be explicit; never silently report a clean scan.
- Avoid speculative dependencies, services, databases, or abstractions.
- No source-code network transmission by default.
- AI/LLM services are never required for analysis.
- Public CLI/config/rule/report contracts become compatibility-sensitive once released.
- Performance changes should be backed by benchmarks or measurements.

### Completion gate

A roadmap item should only be checked when its implementation, relevant tests, documentation, and verification are complete. The expected local quality gate is:

```bash
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

---

## Phase 1 — MVP Scanner

**Goal: a useful local scanner as one Rust binary.**

- [x] Rust workspace/crate structure.
- [x] CLI command: `hawk`.
- [x] CLI command: `hawk .`.
- [x] File and directory target resolution.
- [x] Multiple path arguments.
- [x] Recursive file discovery.
- [x] Default ignore directories.
- [x] Language detection.
- [x] Java parser integration.
- [x] Initial AST representation/adapters.
- [x] Basic pattern rules.
- [x] Basic AST rules.
- [x] Severity levels: Critical / High / Medium / Low / Info.
- [x] Finding Model.
- [x] Useful terminal reporter.
- [x] Exit codes suitable for automation.

### MVP command examples

```bash
hawk
hawk .
hawk ./src
hawk ./src/UserService.java
hawk ./src ./scripts
```

The zero-configuration path must remain functional.

---

## Phase 2 — Rule Packs & Configuration

**Goal: make Hawk extensible without recompiling the engine.**

- [x] Human-readable TOML rule definition.
- [x] Rule metadata.
- [x] Rule severity.
- [x] CWE mapping.
- [x] OWASP mapping.
- [x] Remediation guidance.
- [x] Analysis capability declaration (pattern / AST / semantic / dataflow).
- [x] Rule Pack manifest.
- [x] Rule Pack versioning.
- [x] Built-in Java security pack.
- [x] Custom user Rule Packs.
- [x] Project configuration file.
- [x] Include/exclude configuration.
- [x] Rule Pack selection.
- [x] CLI overrides.
- [x] Rule testing command / playground.

Example target:

```bash
hawk ./src --pack java
hawk ./src --pack korea
hawk rule test ./rules/my-rule.toml ./Example.java
```

---

## Phase 3 — More Languages & Semantic Analysis

**Goal: cover the most useful general-purpose languages.**

Priority:

1. Java
2. JavaScript
3. TypeScript
4. Python
5. Go

Potential later languages:

- Kotlin
- C#
- PHP

Framework awareness should be layered over language support:

```text
Java → Spring / Spring Boot / Servlet / MyBatis
JS/TS → Node.js / React / Vue / Express / Next.js
Python → Django / Flask / FastAPI
```

- [x] Java semantic analysis.
- [x] JavaScript AST/semantic analysis.
- [x] TypeScript AST/semantic analysis.
- [x] Python AST/semantic analysis.
- [x] Go AST/semantic analysis.
- [ ] Framework-aware rules where valuable.

---

## Phase 4 — Data Flow Analysis

**Goal: detect real security flows rather than relying only on local patterns.**

Introduce a reusable model:

```text
Source → Propagation → Sanitizer → Sink
```

- [x] Source definitions.
- [x] Sink definitions.
- [x] Sanitizer definitions.
- [x] Variable propagation.
- [x] Assignment tracking.
- [x] Basic control/data-flow graph.
- [x] Method/function boundaries.
- [x] SQL injection rules.
- [x] Command injection rules.
- [x] XSS rules.
- [x] Path traversal rules.
- [x] SSRF-related rules.
- [x] Security-sensitive API rules.

The engine should own data-flow algorithms; Rule Packs should declare security semantics where practical.

---

## Phase 5 — Incremental & Git-Aware Scanning

**Goal: make Hawk extremely fast during everyday development.**

- [x] File hashing.
- [x] Local cache.
- [ ] AST cache.
- [x] Incremental analysis.
- [x] `hawk --changed`.
- [x] `hawk --staged`.
- [ ] Git-aware baseline.
- [x] Pre-commit integration.
- [x] Benchmark suite and performance budgets.
- [x] Parallel file analysis.

Target philosophy:

> Full scans should be fast; changed-code scans should feel immediate.

No database should be introduced solely for caching.

---

## Phase 6 — Baseline & Reporting

**Goal: produce useful security evidence, not just console warnings.**

### Baseline

- [x] `hawk baseline create`.
- [x] Stable finding fingerprints.
- [x] Existing finding suppression.
- [x] New finding detection.
- [x] Fixed finding detection.
- [x] Regression detection.

### Output

- [x] Terminal report.
- [x] JSON output.
- [x] SARIF output.
- [x] HTML Security Assessment Report.
- [ ] PDF report where practical.
- [x] Report metadata.
- [x] Severity summary.
- [x] Finding details.
- [x] Source snippets.
- [x] Remediation guidance.
- [x] CWE/OWASP/Korean-standard mappings.
- [x] Scan statistics and duration.

Reports should be **English-first** for international portability.

---

## Phase 7 — Korean Secure Coding Rule Pack

**Goal: provide a strong Korea-oriented Rule Pack without coupling Korean policy to the core engine.**

- [ ] Research authoritative Korean secure-coding standards.
- [ ] Verify copyright/license/attribution requirements.
- [x] Define independent Hawk rule IDs.
- [ ] Map rules to applicable Korean guidance.
- [x] Implement high-value Java rules first.
- [x] Add CWE mappings where applicable.
- [x] Add OWASP mappings where applicable.
- [ ] Publish the Rule Pack independently.
- [x] Document rule coverage and limitations.

Important: a mapping to a government/industry standard must not imply government certification or endorsement of Hawk.

---

## Phase 8 — Developer Experience

**Goal: make Hawk pleasant enough to use every day.**

- [ ] TUI configuration/inspection.
- [x] `hawk config`.
- [x] Rule discovery.
- [x] Rule explanation.
- [x] `hawk rule test`.
- [ ] Better source highlighting.
- [x] Helpful error messages.
- [x] VS Code integration.
- [x] IntelliJ IDEA integration.
- [x] GitHub Actions integration.
- [x] CI-friendly exit policies.

The TUI is intentionally later than the core CLI and rule engine.

---

## Phase 9 — Community Rule Ecosystem

**Goal: turn rules into an extensible open-source ecosystem.**

- [x] Rule Pack repository conventions.
- [x] Rule Pack validation.
- [x] Rule Pack compatibility metadata.
- [x] Community contribution guide.
- [x] Rule quality/testing guidelines.
- [x] Company/private Rule Pack documentation.
- [ ] Optional future Rule Pack distribution mechanism.

Potential future packs:

```text
hawk-rules-korea
hawk-rules-owasp
hawk-rules-java
hawk-rules-community
hawk-rules-company-example
```

The exact repository/package naming scheme is not finalized.

---

## Long-Term Ideas

These are deliberately **not commitments** yet:

- [ ] Optional SQLite-backed history store if a compelling use case appears.
- [ ] Historical trend visualization.
- [ ] Local vulnerability history.
- [ ] More advanced interprocedural analysis.
- [ ] Control-flow analysis improvements.
- [ ] Taint analysis improvements.
- [ ] Additional languages.
- [ ] Additional security standards.
- [ ] Plugin APIs if external Rule Packs alone prove insufficient.

The project should resist adding infrastructure simply because it is technically possible.

---

## Non-Goals

Hawk should not drift into these goals without an explicit architectural decision:

- Replacing SonarQube.
- Building an enterprise SAST management server.
- Requiring a cloud backend.
- Requiring AI/LLM APIs.
- Requiring a database for normal operation.
- Supporting every programming language.
- Turning the Rust core into a web service by default.

---

## Definition of Success

Hawk succeeds when a developer can install one binary and run:

```bash
hawk .
```

and receive a fast, trustworthy, English security report without:

```text
Cloud
Database
Docker
AI API
Enterprise license
Complex setup
```

while an advanced team can add its own Rule Pack and policy without modifying or recompiling the analysis engine.
