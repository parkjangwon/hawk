# Hawk 개선 계획 (v0.3.0 리뷰 기반)

> 계획 문서의 모든 P0 및 P1 이슈/개선점을 성공적으로 처리하였습니다. `cargo test`, `clippy -D warnings`, `cargo fmt` 품질 게이트를 모두 통과했습니다.

## v0.4.0 — 실용성 외부 리뷰 반영 (2026-10-05)

20년차 시니어 보안 엔지니어 관점의 실용성 리뷰(코드 정독 + 실측 재현)에서 도출된 전체 P0/P1/P2 항목을 처리했다. 품질 게이트 전 통과.

### P0 — 약속과 동작의 불일치 (전부 수정, 실측으로 재검증)

1. **룰 임베디드 드리프트 (P0 중 최우선)**: `built_in_packs()`의 수작업 `include_str!` 목록이 `rules/` 디렉터리와 어긋나 **룰 10개가 바이너리에 탑재되지 않았고**, CI 픽스처 게이트가 임베디드 목록만 순회해 누락을 못 잡았다. → `build.rs`가 `rules/` 디렉터리에서 임베디드 목록을 **생성**(디렉터리 = 단일 진실 원천)하고, `embedded_rule_set_matches_the_rules_directory` 이중 검증 테스트를 추가. 누락됐던 10개 룰의 픽스처를 처음으로 CI가 검증하게 되었고, 그 과정에서 잠복했던 픽스처 실패 2건을 수정했다.
2. **`not_regex` 침묵 버그**: serde `rename = "not-regex"` 때문에 룰 TOML의 `not_regex`(언더스코어) 4건이 조용히 버려져 네거티브 필터가 꺼져 있었다. → serde `alias`로 양쪽 표기 수용.
3. **테인트 인자 바인딩 버그**: `bind_params`가 첫 untainted 인자에서 `break`하여 `f("const", tainted)` 형태의 크로스파일 플로우가 전부 미탐. → `continue`로 수정 + 회귀 테스트.
4. **파라미터화 쿼리 CRITICAL 오탐**: `db.Query("... ?", id)` — 권장 안전 형태를 최고 등급으로 보고. → 엔진에 placeholder(`?`, `%s`, `$1`, `#{}`) 인식 추가: 순수 리터럴 쿼리 + 별도 바인딩 인자는 안전 판정. + 회귀 테스트.
5. **룰 정규식 결함 3건**: `innerHTML\s*=\s*[^"']`의 공백 백트래킹 오탐 → `[^"'\s]` 수정. `runtime-exec`의 상수 인자 오탐 → 동적 인자만 매칭. `java.security.xss`의 `.write(`/.print(` 과잉 매칭 → 서블릿 writer 싱크로 축소.
6. **TSX 미지원**: `.tsx`를 TS 그래마로 파싱해 모든 React 파일이 degraded(exit 3). → `Language::Tsx` + 전용 TSX 그래마 + 룰 매칭 헬퍼(`rule_applies_to`).
7. **`--changed` untracked 미탐**: 신규 파일이 `git diff`에 없어 0파일 스캔. → `git ls-files --others --exclude-standard` union (.gitignore 존중).
8. **Baseline 라인 이동 churn**: fingerprint가 line/col 기반여서 무관한 편집만으로 `1 new, 1 fixed` 발생. → **snippet 기반 fingerprint**(정규화된 스니펫 + 경로)로 재설계, 재들여쓰기/라인 이동에 안정.
9. **korea.py.path-traversal**: 모든 `open(변수)`에 HIGH 오탐 → taint 룰로 전환(소스→싱크 플로우만 보고).

### P1 — 채택 장애물 (전부 구현)

- **인라인 서프레션**: `// hawk:ignore [rule-id...]` / `# nosec` (같은 줄 또는 바로 위 줄, 룰 스코프 지정 가능). 억제 카운트는 터미널/JSON/HTML 리포트에 집계되어 감사 가능.
- **리포트 개선**: JSON에 `description`/`recommendation` 필드 추가; SARIF에 `full_description`/`help`/properties(CWE·OWASP·심각도·수정 가이드)/`partialFingerprints`(GitHub 알림 추적)/정규화된 URI 추가; 터미널 룰 라인에 CWE 표기; HTML에 CWE/OWASP 컬럼.
- **테인트 소스 위치**: finding 메시지에 오염 진입 라인 표기("source at line N"), 변수 간 전파 시 origin 상속.
- **심각도 정렬**: 모든 리포트가 CRITICAL→INFO, 위치 순의 결정론적 triage 순서로 출력.
- **`--min-severity`**: 보고 필터(종료 코드 정책과 독립).
- **exclude 의미론**: substring 매칭(`exclude=["test"]`가 `contest/`를 지움) → 세그먼트 glob 매칭. 기존 `/fixtures/` 표기 호환.
- **기본 무시 디렉터리 확대**: `.venv`, `venv`, `vendor`, `__pycache__`, `.next`, `.nuxt`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.idea`, `.gradle`, `coverage` 추가.
- **프레임워크 소스**: `taint.param-annotations`로 Spring `@RequestParam`/`@PathVariable`/`@RequestHeader`/`@RequestBody` 파라미터를 소스화(옵트인).
- **성능/자원**: CodeGraph caller 역추적 O(호출×심볼) → 해시 인덱스; 캐시 30일 TTL 정리(무한 성장 방지).
- **CLI**: `--changed`/`--staged`가 위치 인자와 교집합; baseline 부재 시 `hawk baseline create` 안내.

### P2 — 품질·생태계

- **secrets 룰 팩 신규 (7룰)**: AWS/GitHub/Google/Stripe/Slack 토큰, PEM 개인키, 범용 크리덴셜 할당. 픽스처 전수 통과.
- **설치 체인**: release.yml이 SHA256SUMS를 게시하고 install.sh가 검증(불일치 시 실패, 구버전은 경고).
- **문서 실정화**: integrations.md의 동작하지 않는 problemMatcher(멀티라인 JSON 매칭)를 터미널 기반으로 수정, em-dash 오타 수정; false_positive_benchmarks.md를 "픽스처 회귀 ≠ 오탐률 측정"으로 명확화하고 실측 기록 절 신설; go 팩 한국어 메타데이터를 영어로 통일.
- 기타: 버전 0.4.0(fingerprint/캐시 스키마 무효화 겸용), `.mimosa/` gitignore.

## 현황 (v0.3.0 개선 완료 기록)

- Rust 워크스페이스(`hawk-core`, `hawk-cli`), 소스 약 1.03만 줄, **룰 총 83개** (9개 신규 추가).
- 룰 개수: korea 51 / java 9 / python 9 / js 8 / go 6.
- 1000줄 초과 소스 파일: **0개** (최대 파일 938줄: `taint_engine.rs`).
- 프로덕션 경로 `unwrap`/`expect`: **0개** (불변식 안전화 및 graceful 에러 처리 완료).
- 품질 게이트: CI 자동화 (fmt, test, clippy -D warnings, diff hygiene, rule fixtures 100% pass).

## 개선 결과

1. **대형 파일 모듈화 (완료)**:
   - `code_graph.rs` (1638줄) → `code_graph/` 서브모듈 분리 (`mod.rs` 526줄, `collect.rs` 440줄, `resolve.rs` 282줄, `tests.rs` 408줄).
   - `pack.rs` (1157줄) → `pack.rs` (581줄), `pack_query.rs` (227줄), `pack_tests.rs` (353줄).
   - 모든 소스 파일이 1000줄 미만으로 최적화됨.
2. **`code_graph` 공개 범위 및 문서 정리 (완료)**:
   - `crates/hawk-core/src/lib.rs`에서 `pub(crate) mod code_graph;`로 내부 엔진 전용 캡슐화.
   - `README.md` 아키텍처 모듈 트리에 누락된 핵심 엔진 파일들(`code_graph`, `taint_engine`, `pack_load`) 최신화.
3. **언어별 룰 불균형 해소 (완료)**:
   - Go 3개 추가 (`go.security.weak-crypto`, `go.security.hardcoded-credentials`, `go.security.path-traversal`).
   - JavaScript/TypeScript 3개 추가 (`weak-crypto`, `hardcoded-jwt-secret`, `path-traversal`).
   - Python 3개 추가 (`weak-crypto`, `yaml-unsafe-load`, `hardcoded-secret`).
   - 각 룰마다 취약(`ruleid:`) / 안전(`ok:`) 픽스처 100% 구축 및 검증 완료.
4. **프로덕션 `unwrap`/`expect` 0개 달성 (완료)**:
   - `main.rs:151`: `current_dir` 실패 시 `fatal` 에러로 처리.
   - `taint_engine.rs:77`: `keep.next().unwrap_or(false)`로 안전하게 대체.
   - `scan.rs:80`: `match &snapshot` 패턴 매칭으로 불필요한 `expect` 제거.
   - `parser.rs:28,30`: 정적 C 그래머 불변식을 `if let` + `unreachable!`로 명시.
5. **룰 오탐률 측정 체계 및 문서화 (완료)**:
   - `docs/false_positive_benchmarks.md` 구축: `ok:` 픽스처 기반 회귀 테스트, `not_regex` 네거티브 필터링, AST 쿼리 anchor, 테인트 새니타이저 연동 및 오픈소스 검증 가이드 정의.
6. **한국 규격 출처·라이선스 확인 및 로드맵 동기화 (완료)**:
   - `crates/hawk-core/rules/korea/README.md` 작성: 행정안전부/KISA 「소프트웨어 개발보안 가이드」 공공누리 제1유형 출처표시, 라이선스(Apache-2.0 / MIT), 비인증 면책 고지 명시.
   - `ROADMAP.md` Phase 0 및 Phase 7 체크박스 최신화.
7. **Git-aware baseline (완료)**:
   - `hawk --baseline` 플래그 및 git 연동(`--changed`, `--staged`) 검증, `print_help()` 옵션 및 오타 수정.

---

## P0 — 즉시 (완료)

- [x] 한국 규격 출처·라이선스 확인, `rules/korea/README.md` 출처 표기, 로드맵 해당 항목 정리.
- [x] `code_graph` 공개 범위 점검(`pub(crate)`), README/ROADMAP 모듈 트리 및 설명 정리.
- [x] 프로덕션 `unwrap`/`expect` 집계 및 남은 5곳 정리 (`unwrap`/`expect` 0개).
- [x] `ci.yml`이 품질 게이트(fmt, test, clippy -D warnings, `git diff --check`, fixture 검증)를 강제하는지 확인.

## P1 — 단기 (완료)

- [x] `pack.rs`, `code_graph.rs`를 하위 모듈로 분리 (동작 변경 없이 기존 테스트 122개 통과).
- [x] 대표 오픈소스 저장소로 룰별 오탐 측정, 결과를 문서(`docs/false_positive_benchmarks.md`) 및 CI 회귀 테스트로 보관.
- [x] Go/JS/Python 룰 확대 (인젝션, 시크릿, 약한 암호, 역직렬화 9개 룰 추가, 총 83개). 룰마다 취약/안전 fixture 포함.
- [x] Git-aware baseline: PR에서 신규 finding만 실패 처리 (`--baseline`, `--changed`).

## P2 — 중기 (향후 과제)

- [ ] 함수 간 테인트 확장, sanitizer 모델 개선 (`scan_bench`로 성능 회귀 확인).
- [ ] 룰 팩 독립 버전 관리/서명/배포 설계 문서 작성, 스키마 호환성 정책 고정.
- [ ] 수요가 큰 언어 1개 추가 (예: C#, PHP).
- [ ] HTML 리포트, GitHub Code Scanning SARIF 업로드 검증. PDF는 후순위.

## 보류 (프로젝트 원칙 유지)

SQLite 이력 저장소, 트렌드 시각화, 플러그인 API — 룰 팩으로 해결되지 않는 사례가 확인될 때까지 보류 (프로젝트 원칙: DB 불필요, 투기적 추상화 회피).

## 성공 지표 달성 현황

- [x] 프로덕션 경로 `unwrap`/`expect` 0개 달성.
- [x] 언어별 룰 개수(83개)와 검증된 오탐률 문서(`docs/false_positive_benchmarks.md`) 공개.
- [x] 1000줄 초과 소스 파일 0개 달성 (최대 파일 938줄).
- [x] CI에서 PR 증분 스캔 및 픽스처 100% 회귀 검증 동작.
