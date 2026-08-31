# Hawk 🦅

[![CI](https://github.com/parkjangwon/hawk/actions/workflows/ci.yml/badge.svg)](https://github.com/parkjangwon/hawk/actions/workflows/ci.yml)
[![Dependency audit](https://github.com/parkjangwon/hawk/actions/workflows/audit.yml/badge.svg)](https://github.com/parkjangwon/hawk/actions/workflows/audit.yml)

**Local-first static security analysis for developers.**

Hawk is an open-source, developer-first static application security testing (SAST) tool designed to run locally on a developer's machine. It analyzes source code without requiring a cloud service, database, AI API, or external middleware.

> **Your code stays on your machine.**
>
> **No AI. No Cloud. Just Secure Coding.**

## Core Concepts

Hawk is intentionally not a competitor to SonarQube or an attempt to reproduce a large enterprise security platform. Its purpose is narrower and practical: provide a free, open-source alternative for developers who want fast local secure-coding checks without purchasing a commercial SAST license.

### Principles

- **Local-first** — source code is analyzed locally and is not sent to a remote service by default.
- **Fast** — a native Rust binary, parallel analysis, and eventually incremental analysis/caching should make local scanning fast.
- **Free & Open Source** — no paid license is required to use the core tool.
- **No AI required** — analysis must remain deterministic and useful without LLMs or external AI APIs.
- **No database required** — project configuration, rules, baseline, and cache are file-based.
- **Customizable** — security rules are separate from the analysis engine and can be composed into Rule Packs.
- **Developer-first** — `hawk` should be useful immediately with zero configuration, while advanced users can customize policies deeply.
- **English reports** — human-readable reports use English to maximize portability and reuse across teams and countries.

## Installation

One-line install (macOS/Linux, x86_64 and arm64) — downloads the latest
release binary for your platform to `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/parkjangwon/hawk/main/scripts/install.sh | bash
```

Re-running the script updates hawk to the latest release. Options:

- `HAWK_INSTALL_DIR=/custom/bin` — install directory (default `~/.local/bin`)
- `HAWK_VERSION=v0.3.0` — pin a specific release instead of `latest`

Clean uninstall (binary + user data + `./.hawk` cache in the current
directory):

```bash
curl -fsSL https://raw.githubusercontent.com/parkjangwon/hawk/main/scripts/uninstall.sh | bash
```

Prebuilt binaries for Linux (x86_64/aarch64), macOS (x86_64/aarch64), and
Windows (x86_64) are published on the
[releases page](https://github.com/parkjangwon/hawk/releases).

## Basic Usage

The CLI should keep the common case extremely simple:

```bash
hawk
hawk .
hawk ./src
hawk ./src/UserService.java
```

- `hawk` — scan the current working directory.
- `hawk .` — scan the current directory; equivalent to `hawk`.
- `hawk <directory>` — scan a directory recursively.
- `hawk <file>` — scan one file.
- Multiple files/directories should also be accepted eventually: `hawk ./src ./scripts`.

Git-oriented modes make Hawk fast for every-day development and useful alongside Git and AI coding agents:

```bash
hawk --changed           # working-tree changes vs the index
hawk --staged            # staged changes
hawk --fail-on-severity high .   # exit 2 only for HIGH+ findings (CI-friendly)
hawk --format sarif -o report.sarif .
hawk --format html -o report.html .
```

Reports list **every loaded rule category**, so a clean category reads
"no findings" instead of silently disappearing — you can always tell that
the scan ran and what it covered:

```text
2 findings in 144 file(s)
27 file(s) skipped (0 issue(s) resolved by ignoring them

Categories (24):
  availability:                  3 rules, no findings
  command-injection:             8 rules, no findings
  sql-injection:                 5 rules, 1 finding
  xss:                           7 rules, no findings
  ...
```

Rule tooling:

```bash
hawk rule list
hawk rule explain java.security.sql-injection
hawk rule test my-rule.toml fixture.java      # Semgrep-style ruleid/ok + taint aware
hawk rule validate ./my-pack
hawk baseline create | status
hawk config
```

Cross-file taint analysis runs during normal scans: the project-wide symbol
and call-edge index resolves calls to their definitions, so a sink inside a
service class reached from a controller is reported at the call site,
following multi-hop chains (handler → service → repository) with cycle
guards. Callee resolution uses the strongest available signal, in order:

1. import bindings (`import { deleteUser } from "./UserService"`,
   aliases and `import * as ns` namespaces included; Python `from x import y`)
2. declared receiver types with inheritance — `UserService service` resolves
   `service.deleteUser` to `UserService.deleteUser`, falling back through the
   `extends` chain, then `implements` interfaces, then concrete classes that
   implement an interface-typed receiver (bodyless interface declarations are
   skipped in favor of real implementations)

This keeps Hawk useful without sending the source to an external AI/SaaS
service; analysis stays fully local.

## Architecture Direction

Hawk should remain a native local tool rather than becoming a client/server application.

```text
CLI / TUI
    │
    ▼
Config (TOML)
    │
    ▼
File Discovery / Scope
    │
    ▼
Parser / AST / Semantic / Data Flow
    │
    ▼
Rule Engine ◀── External Rule Packs
    │
    ▼
Finding Model
    │
    ├── Terminal
    ├── JSON
    └── SARIF
    │
    ▼
Report Engine
    ├── HTML
    └── PDF
```

The core implementation is **Rust**, and language parsers use Tree-sitter grammars.

```text
hawk-cli (crates/hawk-cli)
  ├─ main.rs        CLI: args, subcommands (rule, baseline, config), exit codes
  └─ hawk-core (crates/hawk-core)
      ├─ scope.rs    path/argument → File|Directory targets
      ├─ discovery.rs deterministic recursive traversal (ignored dirs, no symlinks)
      ├─ language.rs extension → Language (java/js/ts/py/go)
      ├─ parser.rs, ast.rs  Tree-sitter behind SyntaxTree/AstNode adapters
      ├─ semantic.rs symbol collection (types/functions/variables)
      ├─ taint.rs     intraprocedural source→sanitizer→sink engine (Java)
      ├─ pack.rs      rule packs (pattern/query/taint capabilities), DSL loader
      ├─ config.rs    hawk.toml discovery + parsing + precedence
      ├─ cache.rs, git.rs, baseline.rs  incrementality and baselining
      ├─ reporter.rs  terminal reporter (human)
      └─ report.rs    JSON / SARIF 2.1.0 / HTML report models
```

## Analysis Model

Hawk should evolve through progressively deeper analysis capabilities:

1. **Pattern analysis** — simple and fast security patterns.
2. **AST analysis** — structural source-code matching.
3. **Semantic analysis** — types, methods, annotations, framework-aware meaning.
4. **Data-flow analysis** — track values from security-sensitive sources to sinks.
5. **Interprocedural analysis** — follow flows across method/function boundaries.
6. **Code-graph analysis** — index the project's architecture (symbols + call
   edges) once per scan; resolve cross-file callees and report sinks reached
   through real call chains.

Not every rule needs the deepest analysis level. Rules should declare the analysis capability they require where appropriate.

For example, SQL injection analysis may model:

```text
Source → Propagation → Sanitizer → Sink
```

A source could be an HTTP parameter and a sink could be SQL execution. The engine, not the rule file, should own the complicated graph/data-flow algorithms.

## Rule System

The rule system is one of Hawk's most important extension points.

Rules should be external and versionable rather than hard-coded exclusively into the Rust binary. A declarative format such as **TOML** is preferred for rule definitions because rules should be readable and maintainable by humans.

Conceptually:

```text
Rule
  ↓
Rule Pack
  ↓
Policy
```

Examples of Rule Packs:

- Korea / Korean secure-coding rules
- OWASP mappings
- CWE mappings
- Java security
- JavaScript / TypeScript security
- Framework-specific rules
- Organization/company policies
- Community rules
- Personal custom rules

A Rule Pack should be independently versioned and should not require recompiling Hawk.

A future Rule Pack may look conceptually like:

```text
korea-secure-coding/
├── pack.toml
├── rules/
│   ├── JAVA-001.toml
│   ├── JAVA-002.toml
│   └── ...
└── README.md
```

The rule format should describe **what is dangerous** and the analysis engine should describe **how to analyze it**. Complex analysis algorithms must not be forced into a configuration format.

## Configuration

Project configuration should use a human-editable TOML file, initially envisioned as:

```text
securelint.toml → Hawk project configuration
```

The final filename is intentionally not locked yet and should be decided before implementation.

Configuration should eventually cover:

- project metadata
- include/exclude paths
- rule packs
- severity policy
- report format/output
- baseline
- language/framework settings
- future analysis options

CLI arguments should override project configuration when both are present.

The intended precedence is:

```text
Defaults → Project Config → CLI Arguments
```

Hawk should support a zero-configuration first run: `hawk .` should work without requiring the user to create a configuration file.

## Scope and File Discovery

Scope and analyzable files are separate concepts.

```text
Requested Scope
    ↓
Include / Exclude
    ↓
Ignore Rules
    ↓
Language Detection
    ↓
Supported Files
    ↓
Analysis
```

Hawk should naturally ignore irrelevant/generated directories such as `.git`, `node_modules`, `target`, `build`, and `dist` where appropriate, while allowing users to customize exclusions.

## Languages

The initial language set should focus on common development languages rather than attempting to support every language:

- Java
- JavaScript
- TypeScript
- Python
- Go

Potential later additions include Kotlin, C#, and PHP.

React, Vue, Node.js, Spring, MyBatis, Express, Next.js, Django, Flask, FastAPI, etc. should be treated as **framework/runtime awareness layered over a language**, not as separate programming languages.

CSS is not an initial security-analysis priority. HTML may be useful later for web-security analysis such as XSS-related flows.

## Findings

Analysis results should first become a normalized internal **Finding Model**. Reporters should consume findings rather than being embedded inside analysis rules.

A finding should eventually contain fields such as:

```text
rule_id
rule_name
title
description
severity
confidence
language
framework
file
line
column
code_snippet
cwe
owasp
category
recommendation
fingerprint
```

Security findings should explain *why* they were reported. For data-flow findings, the report should ideally show the source → propagation → sink path.

High-quality results and low false-positive rates are more important than maximizing the raw number of findings.

## Reports

Reporting is a first-class feature, not an afterthought.

Hawk should support both human-readable and machine-readable output.

### Human-readable

- Terminal output
- HTML security assessment report
- PDF report, derived from the report model/HTML pipeline when practical

### Machine-readable

- JSON
- SARIF

The report should include enough scan metadata to make the result auditable, including Hawk version, Rule Pack versions, rule count, language/file statistics, scan duration, and timestamp.

Reports should be in **English** for broad reuse.

A report should provide severity summaries, **per-category coverage (every
loaded category is listed, zero-finding categories explicitly marked "No
findings")**, individual findings, locations, rule/CWE/OWASP mappings where
available, code context, remediation guidance, and scan metadata.

## Baseline and Incremental Analysis

Existing vulnerabilities should not make local adoption impractical. Hawk should eventually support a file-based baseline:

```text
.securelint/
├── baseline.json
├── cache/
└── reports/
```

A baseline allows existing findings to be accepted while highlighting newly introduced findings.

Incremental scanning and caching are important parts of the **fast** principle. SQLite is deliberately not required for this. File hashes, AST caches, and analysis artifacts can remain local and file-based.

## Storage / Middleware Philosophy

Hawk is intentionally **not** a server application.

There is no planned mandatory:

- PostgreSQL/MySQL
- SQLite database
- Redis
- Docker service
- middleware layer
- cloud backend
- AI API

The preferred distribution model is a native Rust executable plus project/config/rule files.

If a future feature needs persistent storage, storage should be abstracted behind an interface so a file implementation can exist first and an optional SQLite implementation can be introduced later without changing the analysis core. SQLite is **not part of the initial architecture**.

## Git / IDE / Agent Integration

Future integrations should build on the same analysis engine:

```text
AI Agent / IDE / Git Hook / CI
            │
            ▼
          Hawk
            │
            ▼
       Finding Model
```

Hawk does not need AI to operate. AI agents can optionally use Hawk as an independent local security verifier after code generation/modification.

Planned integrations include:

- Git changed/staged scans
- pre-commit hooks
- GitHub Actions / CI
- VS Code
- IntelliJ IDEA
- TUI configuration and inspection

## Design Decisions Still Open

The following must be explicitly designed before implementation becomes substantial:

- final project/config naming conventions
- exact Rule DSL/TOML schema
- Rule Pack manifest/versioning format
- Finding schema and stable fingerprint strategy
- report schema and HTML design
- baseline semantics
- ignore/exclusion semantics
- plugin architecture, if needed
- exact language/framework parser strategy
- licensing
- official mappings and licensing/attribution requirements for Korean secure-coding, CWE, OWASP, and other external standards

## Non-Goals

Hawk is not intended to initially become:

- a SonarQube replacement
- a full enterprise security management server
- a cloud SAST SaaS platform
- an AI code-review service
- a database-backed vulnerability management system
- an all-language analyzer

The goal is a **small, fast, local, free, extensible security analyzer for developers**.

## Project Status

Hawk is **feature-complete against the ROADMAP** (Phases 0–9 implemented): a single Rust binary that scans a
project with `hawk .` and produces fast, deterministic reports in terminal, JSON, SARIF, or HTML formats.
Rule Packs are versionable TOML data (with tree-sitter query and taint capabilities), the engine ships
Java/JavaScript/TypeScript/Python/Go parsers, and Git-aware (`--changed`/`--staged`), incremental-cache,
baseline, and `--fail-on-severity` workflows make it usable in CI. Some deeper integrations (a standalone
TUI, an independently published Korean rule pack, PDF output, prefix wide performance budgets) remain future
work; see [ROADMAP.md](ROADMAP.md) for the exact checklist.

## Status

Quality gate (fmt/clippy/test/diff) is green on the default branch; the ROADMAP checklist tracks which
items are complete at a glance.

## Development Philosophy

Hawk should be developed as a **small, composable security-analysis engine**, not as a collection of CLI features.

### TDD is a project rule

New behavior should be driven by tests. Prefer this cycle:

```text
Red → Green → Refactor → Verify
```

Every meaningful feature should have the smallest appropriate test layer:

- **Unit tests** for pure domain logic and analysis components.
- **Integration tests** for component boundaries and the scan pipeline.
- **Fixture tests** for security rules using vulnerable and safe source examples.
- **CLI/E2E tests** for user-visible behavior and exit-code contracts.

Tests must be deterministic and must not require a network connection, cloud service, AI API, database, or developer-specific machine state.

### Quality gates

Before a change is considered complete, the project should pass at minimum:

```bash
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

As CI evolves, these checks should become mandatory repository gates.

### Small-step implementation

Prefer narrow, independently verifiable changes over large rewrites. A feature should be implemented in vertical slices when practical:

```text
Domain → Test → Implementation → Integration → Verification
```

Do not add infrastructure, abstractions, dependencies, or configuration before a concrete requirement justifies them. Avoid speculative generalization.

### Architecture boundaries

Keep responsibilities explicit:

- CLI handles arguments, presentation selection, and process-level concerns.
- Core owns scanning, parsing, analysis, rules, findings, and report models.
- Rules describe security intent; reusable analysis algorithms belong to the engine.
- Reporters consume normalized results and do not perform security analysis.
- Configuration and Rule Packs are data, not hidden application logic.

Prefer dependency direction toward stable domain/core code. Avoid circular dependencies and avoid coupling the core engine to a particular output format or UI.

### Determinism and reproducibility

The same source, configuration, Rule Pack versions, and Hawk version should produce the same findings regardless of machine or execution order, except for explicitly documented metadata such as timestamps.

File discovery, rule execution, and report ordering should therefore be deterministic. Finding fingerprints must remain stable across scans when the underlying finding has not materially changed.

### Security analyzer quality

A security scanner is only useful when developers trust its results. Therefore:

- Prefer high-signal findings over noisy pattern counts.
- Every rule should have a clear rationale and remediation guidance.
- False positives should be treated as a first-class quality problem.
- Rules should declare confidence when meaningful.
- Security rules require regression fixtures.
- A rule must not silently change severity or semantics without an intentional versioned change.
- Parser failures must be observable and must never be silently treated as "no vulnerabilities".

### Failure philosophy

Hawk should fail **explicitly and safely**. An unreadable file, parser failure, invalid Rule Pack, or invalid configuration must not silently produce a misleading clean result.

At the same time, one bad source file should not unnecessarily abort a whole project scan when the failure can be isolated and reported.

### Backward compatibility

Once the CLI, configuration schema, Rule Pack schema, Finding Model, report formats, or rule IDs become public, treat them as compatibility-sensitive APIs.

Breaking changes should be deliberate, documented, and versioned. Internal implementation details may change freely when the public contracts remain intact.

### Performance philosophy

Performance is a feature, but not at the expense of correctness. Measure before optimizing. Prefer profiling and benchmarks over intuition.

The intended progression is:

```text
Correctness → Determinism → Profiling → Optimization → Benchmark regression guard
```

Parallelism and caching should be introduced only where their complexity is justified by measured workloads.

### Privacy by default

Source code is sensitive. Hawk must not transmit source code, findings, telemetry, or project metadata anywhere by default. Any future network-enabled capability must be explicit, opt-in, documented, and isolated from the local analysis path.

### AI independence

AI may be an optional consumer of Hawk's output, but AI must not be a prerequisite for analysis. A local Hawk scan must remain complete and useful without an LLM, API key, network connection, or external agent.

### Standards and attribution

External standards such as Korean secure-coding guidance, CWE, and OWASP should be treated as references/mappings with appropriate attribution and licensing review. Hawk must not imply certification, endorsement, or official affiliation merely because a Rule Pack maps to an external standard.
