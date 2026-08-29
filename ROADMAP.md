# Hawk Roadmap 🦅

This roadmap records the current agreed direction for Hawk. It is intentionally implementation-oriented so future coding agents can use it as project context without relying on chat history.

## Phase 0 — Architecture & Design

**Status: Current**

Before substantial implementation, settle the following interfaces:

- [ ] Define final architecture and crate/module boundaries.
- [ ] Define the normalized Finding Model.
- [ ] Define the Report Model.
- [ ] Define the Rule DSL / TOML schema.
- [ ] Define Rule Pack manifest and versioning.
- [ ] Define configuration schema and final config filename.
- [ ] Define severity and confidence semantics.
- [ ] Define finding fingerprint/stability rules.
- [ ] Define baseline behavior.
- [ ] Define include/exclude/ignore semantics.
- [ ] Decide parser technology and language-specific AST adapters.
- [ ] Decide licensing and attribution requirements for external rule standards.
- [ ] Document which Korean secure-coding standards/rules can be implemented and how they are attributed.
- [ ] Keep optional future storage extensibility in mind without introducing a database.

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
- [ ] Language detection.
- [x] Java parser integration.
- [x] Initial AST representation/adapters.
- [ ] Basic pattern rules.
- [x] Basic AST rules.
- [x] Severity levels: Critical / High / Medium / Low / Info.
- [ ] Finding Model.
- [ ] Useful terminal reporter.
- [ ] Exit codes suitable for automation.

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

- [ ] Human-readable TOML rule definition.
- [ ] Rule metadata.
- [ ] Rule severity.
- [ ] CWE mapping.
- [ ] OWASP mapping.
- [ ] Remediation guidance.
- [ ] Analysis capability declaration (pattern / AST / semantic / dataflow).
- [ ] Rule Pack manifest.
- [ ] Rule Pack versioning.
- [ ] Built-in Java security pack.
- [ ] Custom user Rule Packs.
- [ ] Project configuration file.
- [ ] Include/exclude configuration.
- [ ] Rule Pack selection.
- [ ] CLI overrides.
- [ ] Rule testing command / playground.

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

- [ ] Java semantic analysis.
- [ ] JavaScript AST/semantic analysis.
- [ ] TypeScript AST/semantic analysis.
- [ ] Python AST/semantic analysis.
- [ ] Go AST/semantic analysis.
- [ ] Framework-aware rules where valuable.

---

## Phase 4 — Data Flow Analysis

**Goal: detect real security flows rather than relying only on local patterns.**

Introduce a reusable model:

```text
Source → Propagation → Sanitizer → Sink
```

- [ ] Source definitions.
- [ ] Sink definitions.
- [ ] Sanitizer definitions.
- [ ] Variable propagation.
- [ ] Assignment tracking.
- [ ] Basic control/data-flow graph.
- [ ] Method/function boundaries.
- [ ] SQL injection rules.
- [ ] Command injection rules.
- [ ] XSS rules.
- [ ] Path traversal rules.
- [ ] SSRF-related rules.
- [ ] Security-sensitive API rules.

The engine should own data-flow algorithms; Rule Packs should declare security semantics where practical.

---

## Phase 5 — Incremental & Git-Aware Scanning

**Goal: make Hawk extremely fast during everyday development.**

- [ ] File hashing.
- [ ] Local cache.
- [ ] AST cache.
- [ ] Incremental analysis.
- [ ] `hawk --changed`.
- [ ] `hawk --staged`.
- [ ] Git-aware baseline.
- [ ] Pre-commit integration.
- [ ] Benchmark suite and performance budgets.
- [ ] Parallel file analysis.

Target philosophy:

> Full scans should be fast; changed-code scans should feel immediate.

No database should be introduced solely for caching.

---

## Phase 6 — Baseline & Reporting

**Goal: produce useful security evidence, not just console warnings.**

### Baseline

- [ ] `hawk baseline create`.
- [ ] Stable finding fingerprints.
- [ ] Existing finding suppression.
- [ ] New finding detection.
- [ ] Fixed finding detection.
- [ ] Regression detection.

### Output

- [ ] Terminal report.
- [ ] JSON output.
- [ ] SARIF output.
- [ ] HTML Security Assessment Report.
- [ ] PDF report where practical.
- [ ] Report metadata.
- [ ] Severity summary.
- [ ] Finding details.
- [ ] Source snippets.
- [ ] Remediation guidance.
- [ ] CWE/OWASP/Korean-standard mappings.
- [ ] Scan statistics and duration.

Reports should be **English-first** for international portability.

---

## Phase 7 — Korean Secure Coding Rule Pack

**Goal: provide a strong Korea-oriented Rule Pack without coupling Korean policy to the core engine.**

- [ ] Research authoritative Korean secure-coding standards.
- [ ] Verify copyright/license/attribution requirements.
- [ ] Define independent Hawk rule IDs.
- [ ] Map rules to applicable Korean guidance.
- [ ] Implement high-value Java rules first.
- [ ] Add CWE mappings where applicable.
- [ ] Add OWASP mappings where applicable.
- [ ] Publish the Rule Pack independently.
- [ ] Document rule coverage and limitations.

Important: a mapping to a government/industry standard must not imply government certification or endorsement of Hawk.

---

## Phase 8 — Developer Experience

**Goal: make Hawk pleasant enough to use every day.**

- [ ] TUI configuration/inspection.
- [ ] `hawk config`.
- [ ] Rule discovery.
- [ ] Rule explanation.
- [ ] `hawk rule test`.
- [ ] Better source highlighting.
- [ ] Helpful error messages.
- [ ] VS Code integration.
- [ ] IntelliJ IDEA integration.
- [ ] GitHub Actions integration.
- [ ] CI-friendly exit policies.

The TUI is intentionally later than the core CLI and rule engine.

---

## Phase 9 — Community Rule Ecosystem

**Goal: turn rules into an extensible open-source ecosystem.**

- [ ] Rule Pack repository conventions.
- [ ] Rule Pack validation.
- [ ] Rule Pack compatibility metadata.
- [ ] Community contribution guide.
- [ ] Rule quality/testing guidelines.
- [ ] Company/private Rule Pack documentation.
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
