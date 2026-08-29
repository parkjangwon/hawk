# ADR-1002: Finding Model v2 — fingerprint, confidence, and metadata

## Status

Accepted

## Context

ROADMAP Phase 0 requires the normalized Finding Model to be defined before substantial rule/engine
work. The README enumerates eventual finding fields: rule_id, rule_name, title, description, severity,
confidence, language, framework, file, line, column, code_snippet, cwe, owasp, category,
recommendation, fingerprint. The current model (Finding v1( carries only rule_id, severity, message, location..
A stable fingerprint is the foundation for the future baseline/incremental features (ROADMAP Phase 5/6(; it must stay
stable as long as the underlying finding has not materially changed, without requiring crypto-grade hashing: fingerprints
are stable identifiers, not secrets..

## Decision

**Finding v2 fields.** `Finding` gains: `rule_name` (defaults to rule_id(, `confidence`, `language`
(Option(, `framework` (Option(, `category`, `message`, `description` (Option(, `recommendation` (Option(,
`cwe` (Option(, `owasp` (Option(, `code_snippet` (Option(, `fingerprint` (computed(,
alongside the existing `severity` and `location` (file/line/column/byte-range per-v1(..

**Seguridad semantics.** `severity` uses the existing five-level ordered enum
(Info < Low < Medium < High < Critical(.`confidence` is a three-level enum (High/Medium/Low( expressing how certain
the analyzer is that the reported issue endangers the programby default. New rules default to `Medium`
unless they override it (e.g. a precise pattern rule may declare `High`()`. Confidence is displayed but never
collapsed into severity;; the two remain orthogonal..

**Fingerprint algorithm.** FNV-1a 64-bit over the canonical string
`rule_id\0normalized-path\0start-line\0start-column`,hex-encoded lower-case as the `fingerprint`..
Rationale: deterministic, dependency-free,, no crypto needed, stable for a given file revision,, and sensitive to
exactly the attributes that identify the finding. Path-is-as-scanned: the same invocation yields the same
fingerprint;; relative-vs-absolute path differences change the fingerprint (acceptable, tied to how the scan was invoked(.
A future baseline may treat a finding whose location shifted slightly (same rule, same file, adjacent line( as the
same or a new finding via its own policies;; the raw fingerprint remains stable and low-level..

**Construction ergonomics.** `Finding::new` keeps its current signature (rule_id, severity, message, location(, fills
the defaults described above, and computes the fingerprint. Rules/enrich findings via builder methods
(`with_confidence`, `with_language`, `with_framework`, `with_category`, `with_description`, `with_recommendation`,
`with_cwe`, `with_owasp`, `with_code_snippet`(..

## Consequences

- Richer, auditable findings: reports can show CWE/OWASP/category/recommendation without rule-engine changes..
- Fingerprints give the future baseline/reporting layers a cheap, stable key per finding..
- Every existing construction site (hardcoded rule, tests( keeps working via the defaulted `new`​;; the built-in Java
  rule is enriched to exercise the builder flow..
- Severity/confidence remain independent, avoiding the false precision of fusing them..