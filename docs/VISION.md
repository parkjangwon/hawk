<!-- I-WANT-GO-HOME: SETUP COMPLETE -->

# Hawk Vision 🦅

**Local-first static security analysis for developers.**

Hawk is an open-source, developer-first static application security testing (SAST) tool that runs
locally on a developer's machine, with no cloud service, database, AI API, or external middleware.

The canonical vision and principles live in the repository root: [README.md](../README.md). This file anchors
the autonomous development loop to that vision.

## Goals

1. A single native binary that scans a project with `hawk .` and returns a fast, deterministic, trustworthy report.
2. The full analysis stack — pattern → AST → semantic → data-flow — grows inside `hawk-core` structure a Rules-are-data architecture.
3. Rule Packs (TOML( can extend the engine without recompiling it; the engine owns the analysis algorithms.
4. Reporting (terminal/JSON/SARIF/HTML/PDF(, baseline (, and incremental/Git-aware scanning make Hawk practical
   enough for everyday and CI use.
5. Developer experience (rule list/explain/test, config inspection, integrations(, a Korean secure-coding
   Rule Pack, and a community rule ecosystem complete the roadmap.
6. Every meaningful behavior is TDD-driven and verified locally with no network/database/AI dependency.

## Non-Goals

Hawk must not become: an enterprise SAST server, a cloud SaaS platform, an AI code-review service,
a database-backed vulnerability manager, or an all-language analyzer. No AI. No Cloud. Just Secure Coding.