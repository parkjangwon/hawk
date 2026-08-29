# ADR-0004: Rule DSL schema and rule-pack layout

## Status

Accepted

## Context

ROADMAP Phase 2 requires human-readable rule definitions in TOML, independently versioned Rule Packs,
and no recompilation of the engine when packs change. The README sketches `pack.toml` + `rules/*.toml`.
Rules must describe *what is dangerous*; the engine describes *how to analyze it*.

## Decision

**Rule file schema** (`*.rule.toml`, one rule per file):

```toml
id = "java.security.runtime-exec"        # required; globally unique
name = "Runtime exec call"               # short display name
description = "..."                      # what is dangerous, when
recommendation = "..."                   # remediation guidance
category = "command-injection"           # free-form security category
severity = "high"                        # info|low|medium|high|critical
confidence = "high"                      # low|medium|high (optional, default medium)
languages = ["java"]                     # language codes the rule applies to
cwe = "CWE-78"                           # optional
owasp = "A03:2021"                       # optional

[pattern]                                 # capability: pattern-analysis
regex = "..."                             # multiline regex, applied to source text
```

A rule file carries exactly one analysis capability block. The `[pattern]` (regex) capability is the
initial one; `[query]` (tree-sitter S-expr) is slotted for Phase 3, and `[taint]` (source/sanitizer/sink)
for Phase 4. The engine maps each capability to its algorithm. Severity/confidence/languages are
canonicalized at load time; an unknown code is an explicit load error — never silently ignored.

**Rule Pack** (directory):

```text
pack.toml
rules/*.rule.toml
```

`pack.toml` declares `name`, `version` (semver-like), `description`, and optional `authors`.
Rule IDs already include a pack-derived prefix by convention (e.g. `java.security-*` for the java pack);
the engine does not enforce a prefix, packs are responsible for their own namespace hygiene.s

**Loading.** Built-in packs are compiled into the binary via `include_str!` (zero runtime config,
deterministic); user packs are loaded from `--pack-dir` and/or config `pack_dirs`. A pack may be
selected/unselected via `--pack`/`packs`[]. The same rule id defined by two loaded packs is a load-time
error (explicit failure, ADR-0003).

**Validation.** `hawk rule validate` (Phase 9/8) parses packs and prints checkable diagnostics; loading
always validates and fails loudly on malformed rules.

## Consequences

- Rule files are data: humans, git history, and validation tools can treat them like config.
- Capabilities stay explicit, matching the analysis-model levels in the README.
- Deterministic ordering: rule iteration follows pack order then file order within a pack.