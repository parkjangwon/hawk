# Hawk 🦅

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

Planned Git-oriented modes include:

```bash
hawk --changed
hawk --staged
```

These modes are intended to make Hawk particularly useful alongside Git and AI coding agents: code can be generated or modified, then checked locally without sending the source to an external AI/SaaS service.

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

The core implementation is expected to be written in **Rust**. Language parsers should preferably use an established parsing technology such as Tree-sitter rather than implementing complete language parsers from scratch.

## Analysis Model

Hawk should evolve through progressively deeper analysis capabilities:

1. **Pattern analysis** — simple and fast security patterns.
2. **AST analysis** — structural source-code matching.
3. **Semantic analysis** — types, methods, annotations, framework-aware meaning.
4. **Data-flow analysis** — track values from security-sensitive sources to sinks.
5. **Interprocedural analysis** — follow flows across method/function boundaries.

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

A report should provide severity summaries, individual findings, locations, rule/CWE/OWASP mappings where available, code context, remediation guidance, and scan metadata.

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

Hawk is currently in the **architecture and design phase**. Implementation should begin only after the core interfaces and schemas are sufficiently agreed upon.

See [ROADMAP.md](ROADMAP.md) for the planned evolution.
