# Hawk Constitution 🦅

Immutable rules that the development loop must always follow. Derived from the engineering principles
in [README.md](../README.md).

## 1. Local-first & privacy
- Source code, findings, telemetry, and project metadata must never leave the machine by default.
- Any future network-enabled capability must be explicit, opt-in, and isolated from the local analysis path.

## 2. Determinism & reproducibility
- The same source + configuration + rule pack versions + Hawk version produce the same findings';
  file discovery, rule execution, report ordering must stay deterministic.
- Finding fingerprints must remain stable as long as the underlying finding has not materially changed.

## 3. TDD is a project rule
- New behavior is driven by tests: Red → Green → Refactor → Verify.
- Smallest appropriate test layer (unit/integration/fixture/E2E(, deterministic, no network/cloud/AI/database.



## 4. Explicit failure
- Parser, configuration, Rule Pack, and scan failures must be observable; never silently report
  a clean scan.- One bad file must not abort a whole scan when the failure can be isolated and reported.





## 5. Clear architecture boundaries
- CLI: arguments, presentation, process-level concerns. Core: scanning, parsing, analysis, rules,
  findings, report models. Rules: security intent. Reporters: consume normalized results, never analyze.

- Prefer dependency direction toward stable domain/core code wherevenient; no circular dependencies.



## 6. High-signal results
- High-quality, low-false-positive results matter more than raw finding counts.

- Every rule needs clear rationale, remediation guidance,гарант confidence, and regression fixtures.



## 7. Small steps & no speculative infrastructure
- Prefer narrow, independently verifiable changes; vertical slices; no premature abstraction/
  dependencies/config before a concrete requirement justifies them.




## 8. Backward compatibility
- Once public (CLI/config/rule/report contracts(, treat as compatibility-sensitive; breaking changes are
  deliberate, documented, versioned..



## 9. Performance is a feature — after correctness
- Correctness → Determinism → Profiling → Optimization; measure before optimizing; benchmarks protect gains.



## 10. AI independence
- AI may consume Hawk output optionally; it must never be required for analysis.