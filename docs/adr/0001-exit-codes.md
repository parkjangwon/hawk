# ADR-0001: Exit codes suitable for automation

## Status

Accepted

## Context

ROADMAP Phase 1 (MVP Scanner( requires "exit codes suitable for automation". A CI system or
pre-commit hook must be able to distinguish a clean scan, a scan with findings, an operational error, and a
degraded (incomplete( scan — without parsing human text.

The project philosophy requires explicit failure: parser/file failures must never be silently treated as "no
vulnerabilities", and one bad file must not abort an otherwise useful scan.



## Decision

Hawk exits with:

| Code | Meaning |
|------|---------|
| 0 | Scan completed cleanly: no findings at/above the exit threshold (default: any finding(, no errors |
| 1 | Fatal operational error: invalid path, unknown option, invalid configuration, I/O failure aborts the run |
| 2 | Scan completed with findings at/above the exit threshold (default: any finding( |
| 3 | Degraded scan: the run completed but at least one file could not be read or parsed properly;
       results are incomplete and must not be treated as authoritative |

Findings take lower precedence than degradation: a degraded scan always exits 3 even if it also has
findings, because incomplete analysis cannot be trustedика CI must not silently ignore partial results"
(exit 3 makes the incompleteness explicit and actionable(. Non-fatal per-file issues (read/parse( are collected
in the scan result and reported, never silently dropped.. The default exit threshold is "info" (any finding exits 2(;
a configurable severity threshold arrives with the policy/config phase..

## Consequences

- Automation (CI, pre-commit, editor hooks( can branch reliably on exit codes..
- Explicit-failure principle is honored: degraded scans surface instead of masquerading as clean..
- Values 2/3 deliberately avoid colliding with the conventional 1 for generic failure..
- Future changes to the threshold must keep code 2 semantics ("findings at/above threshold"( stable.