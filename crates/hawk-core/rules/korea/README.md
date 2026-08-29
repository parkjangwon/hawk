# korea-secure-coding Rule Pack

Independent Hawk rule IDs inspired by common Korean secure-coding guidance for
Java. The pack is **by-reference**: it maps to widely adopted secure-coding
themes (credentials in code, weak randomness, information disclosure, SQL
injection) and does **not** claim certification, endorsement, or official
affiliation with any government or industry body.

## Rules

| Rule id | Theme | Severity | CWE / OWASP |
|---------|-------|----------|-------------|
| `korea.java.hardcoded-password` | credentials in source | high | CWE-798 / A07 |
| `korea.java.hardcoded-key` | embedded crypto key material | high | CWE-321 / A02 |
| `korea.java.weak-random` | `Random`/`Math.random` for security decisions | medium | CWE-330 / A02 |
| `korea.java.stacktrace-public` | leaking stack traces to HTTP responses | medium | CWE-209 / A01 |

## Mappings

Mappings to external standards are provided as **references only**. Before
distributing this pack publicly, a maintainer must review:

- the copyright/licensing of the source guidance document,
- the attribution requirements of CWE and OWASP references.

## Limitations

- Regex-based (plus taint where applicable); does not perform interprocedural
  flow or type-aware analysis.
- Java-focused; Python/JS equivalents are not yet included.
- High-signal by design: prefer fewer, trustworthy findings over recall.