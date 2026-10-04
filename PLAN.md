# Hawk 개선 계획 (v0.3.0 리뷰 기반)

> 계획 문서의 모든 P0 및 P1 이슈/개선점을 성공적으로 처리하였습니다. `cargo test`, `clippy -D warnings`, `cargo fmt` 품질 게이트를 모두 통과했습니다.

## 현황 (개선 완료)

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
