# Hawk Rule Ecosystem

Hawk rules are data. They live in **Rule Packs** — versioned directories that
anyone can publish, share, or vendor, exactly like code libraries.

## Anatomy of a Rule Pack

```text
hawk-rules-myorg/
├── pack.toml            # name, version, description, authors
└── rules/
    ├── org.java.password.rule.toml
    └── org.java.random.rule.toml
```

### pack.toml

```toml
name = "myorg"
version = "1.2.0"
description = "Organization-specific secure-coding rules."
authors = ["Security Team"]
```

### Rule file (pattern capability)

```toml
id = "myorg.java.random"
name = "Use of Math.random"
description = "Math.random is not cryptographically secure."
recommendation = "Use SecureRandom."
category = "weak-crypto"
severity = "medium"
confidence = "high"
languages = ["java"]
cwe = "CWE-330"
owasp = "A02:2021"

[pattern]
regex = "Math\\.random\\s*\\(|new Random\\s*\\("
not-regex = "\\.randomNumber\\("    # exclude an allowed alternative
fix = "new java.util.SecureRandom()" # reported as a "Suggested fix"
```

### Capabilities

| Capability | What it matches | Notes |
|-----------|-----------------|-------|
| `[pattern]` | A regex over the raw source text | Fast, simple |
| `[query]`  | A tree-sitter S-expression AST pattern | `tree-sitter = "(method_invocation) @call"`
| `[taint]`  | Data-flow sources → sanitizers → sinks | `sources`/`sanitizers`/`sinks` string lists |

## Rule IDs

- Global uniqueness is required. Prefix with the pack name
  (`<pack>.<language>.<topic>`).
- Prefer stable, descriptive ids: `java.security.sql-injection`.

## Testing rules (Semgrep-style fixtures)

Annotation-drive the expected outcomes right in the fixture file:

```java
// ruleid: myorg.database          ← this line MUST produce a finding
String sql = "SELECT * FROM u WHERE id =" + userId;
// ok: myorg.database               ← this line MUST produce no finding
String sql2 = db.escapeSql("SELECT 1");
```

Run `hawk rule test rule.toml fixture.java`. The command exits non-zero on any
mismatch, so it can gate CI.

## Sharing packs

1. Keep the pack in its own repository (or a `rules/` directory).
2. Publish a semver tag; bump it on any behavioral change.
3. Consumers reference it:
   ```toml
   # hawk.toml
   pack-dirs = ["vendor/myorg-rules"]
   packs = ["java", "myorg"]
   ```
4. Validate before publishing:
   ```
   hawk rule validate ./myorg-rules
   ```
   The loader rejects duplicate rule ids and unknown severity/confidence values
   explicitly — a broken pack can never silently mean "no findings".

## Compatibility

Rule files declare semantics the engine executes; as long as the schema fields
you use are supported, rules stay valid across Hawk versions. Track the schema
version in `pack.toml` under `metadata.compat` if you depend on very recent
features.