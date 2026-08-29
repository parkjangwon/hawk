# Contributing to Hawk

Thanks for helping! Hawk follows small, TDD-driven, deterministic changes.

## Ground rules

- **TDD**: new behavior lands with tests. Red → Green → Refactor → Verify.
- **No speculative infrastructure.** Add abstractions only when a concrete
  requirement justifies them.
- **Determinism:** same input + same rule packs + same version → same report.
- **Explicit failure:** parser/config/rule failures are never silently
  reported as "no vulnerabilities".
- **Privacy:** analysis must never require a network connection, and the default
  path must not transmit source code anywhere.
- **AI independence:** nothing in the local scan path may depend on an LLM or
  external service.

## Quality gates (must pass locally)

```bash
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

## Where does what live?

| Area | Crate/module |
|------|--------------|
| CLI, arguments, exit codes | `crates/hawk-cli/src/main.rs` |
| Scope, discovery, language | `crates/hawk-core/src/{scope,discovery,language}.rs` |
| Parsers / AST | `crates/hawk-core/src/{parser,ast}.rs` |
| Rule packs & DSL | `crates/hawk-core/src/pack.rs`, `rules/*` |
| Taint analysis | `crates/hawk-core/src/taint.rs` |
| Semantic symbols | `crates/hawk-core/src/semantic.rs` |
| Reports (JSON/SARIF/HTML) | `crates/hawk-core/src/report.rs` |
| Baseline | `crates/hawk-core/src/baseline.rs` |
| Cache / git-aware | `crates/hawk-core/src/{cache,git}.rs` |

## Adding a rule

1. Create `rules/<pack>/<id>.rule.toml` (see `docs/rules-ecosystem.md`).
2. Add a Semgrep-style fixture under the corresponding test dir with
   `// ruleid:` / `// ok:` annotations.
3. Wire the rule into the built-in pack loader only if it belongs in the pack;
   otherwise keep it in a separate pack and validate with
   `hawk rule validate`.

## Adding a feature (vertical slice)

Implement in slices: domain → test → implementation → integration → verify.
Each slice is a small, independently committable step. Commit messages are one
line, imperative, in English (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).