# Hawk 룰 오탐률(False Positive) 측정 체계 및 벤치마크

정적 분석 도구의 실효성은 미탐(False Negative) 방지뿐만 아니라 **오탐(False Positive) 억제**에 의해 결정됩니다. 과도한 오탐은 개발자의 경고 피로를 유발하여 도구의 신뢰성을 떨어뜨립니다.

Hawk의 오탐 방지는 두 개의 **서로 다른** 계층으로 구성됩니다. 이 둘을 혼동하지 않는 것이 중요합니다:

1. **픽스처 회귀 (`ok:` 어노테이션)** — 알려진 안전 패턴이 다시 오탐을 내지 않는다는 *회귀 방지* 장치입니다. 픽스처는 저작자의 가정을 검증할 뿐 실세계를 대표하지 않으므로, 이것만으로 "오탐률 0%"를 주장할 수 없습니다.
2. **실측 벤치마크 (이 문서 §3)** — 실제 코드베이스에 스캔해서 **측정하고 기록하는** 절차입니다. 오탐률 주장은 여기에 기록된 결과로만 뒷받침됩니다.

---

## 1. 오탐 방지 및 측정 체계

### 1.1 `ok:` 어노테이션 기반 회귀 테스트
Hawk의 모든 룰은 `rules/<pack>/fixtures/<ruleid>.<ext>` 파일 내에 취약 패턴(`ruleid:`)과 함께 **정상적인 안전 코드(`ok:`)**를 반드시 포함해야 합니다.

```go
// 취약한 호출 -> 반드시 탐지되어야 함 (Finding)
// ruleid: go.security.weak-crypto
h := md5.New()

// 안전한 대체 코드 -> 절대로 탐지되면 안 됨 (False Positive Guard)
// ok: go.security.weak-crypto
h256 := sha256.New()
```

- 만약 `ok:` 라인에서 탐지가 발생하면 CI(`every_built_in_rule_has_a_fixture_that_passes`)가 즉시 실패합니다.
- `embedded_rule_set_matches_the_rules_directory` 테스트가 임베디드 룰 수가 디스크의 룰 파일 수와 일치하는도 검증합니다(build.rs 생성 이중 안전장치).
- **한계**: 픽스처는 룰 저작자가 예상한 형태만 검증합니다. 실제 코드의 포맷 변형(예: `=` 뒤 공백)은 커버되지 않습니다 — 이는 §3 실측이 존재하는 이유입니다. (실례: `innerHTML\s*=\s*[^"']` 정규식은 `[^"']`가 공백을 매칭하는 백트래킹 때문에 `ok:` 픽스처를 통과한 채 실전에서 상수 할당을 오탐했습니다.)

### 1.2 엔진 레벨의 오탐 억제 기술
Hawk은 단순한 정규표현식 매칭에 의존하지 않고 다음 기술로 오탐을 차단합니다:

1. **`not_regex` 네거티브 필터링**: 더미 데이터(`placeholder`, `dummy`, `test`, `example`)가 포함된 라인을 배제. `not-regex`(하이픈)와 `not_regex`(언더스코어) 표기를 모두 받습니다.
2. **Tree-sitter AST & Predicate 평가**: 정적 텍스트 매칭 대신 문법 노드(`method_invocation`, `call_expression`)를 식별하고, 인자 형태(`anchor`, `#not-match?`)를 검사.
3. **데이터 흐름 & 새니타이저(Sanitizer) 추적**: 이스케이프 함수나 유효성 검증기를 거친 변수는 taint 상태를 정화.
4. **파라미터화 인식 (엔진 레벨)**: 싱크의 쿼리 문자열이 placeholder(`?`, `%s`, `$1`, `#{}`)를 포함한 순수 문자열 리터럴이고 오염 데이터가 별도 바인딩 인자로 전달되면 안전 판정. 파라미터화 쿼리는 권장 해법이므로 오탐이어야 합니다.
5. **프레임워크 소스 옵트인**: `param-annotations`로 선언된 애노테이션(`@RequestParam` 등)만 메서드 파라미터를 소스로 취급 — 일반 파라미터는 오염되지 않습니다.
6. **인라인 서프레션**: `// hawk:ignore [rule-id...]` / `// nosec`로 라인 단위 억제. 개발자가 오탐을 소스에서 즉시 치울 수 있으면, 억제 사유도 코드 리뷰에 남습니다.

---

## 2. 언어별 룰 팩 회귀 현황

아래 표의 "픽스처"는 §1.1 회귀 테스트 현황이며 오탐률 측정값이 아닙니다.

| 룰 팩 (`pack`) | 룰 수 | 픽스처 | 회귀 상태 |
|---|---|---|---|
| **korea** | 51 | ruleid/ok 전수 | ✅ CI 게이트 통과 |
| **java** | 9 | ruleid/ok 전수 | ✅ CI 게이트 통과 |
| **python** | 9 | ruleid/ok 전수 | ✅ CI 게이트 통과 |
| **js** | 8 | ruleid/ok 전수 | ✅ CI 게이트 통과 |
| **go** | 6 | ruleid/ok 전수 | ✅ CI 게이트 통과 |
| **secrets** | 7 | ruleid/ok 전수 | ✅ CI 게이트 통과 |

---

## 3. 실측 벤치마크 절차

신규 룰 개발 시 다음 표준 오픈소스 레포지토리의 소스를 대상으로 스캔하여 오탐 빈도를 **측정하고, 이 절에 결과를 기록**합니다:

- **Java**: Spring PetClinic, WebGoat
- **Python**: Flaskr, OWASP Juice Shop (백엔드)
- **JS/TS**: Express Starter, RealWorld Example App
- **Go**: Gin Examples, Kubernetes client-go 샘플

측정 방법:
```bash
hawk --pack <pack-name> /path/to/repo --format json -o audit-report.json
```

리포트 내의 모든 finding을 수동 검토하여 오탐으로 판명된 패턴은 해당 룰의 `not_regex`, AST 쿼리 anchor, 또는 (구조적 문제면) taint 전환으로 정밀화합니다. 최소 기준: **클린 코드만으로 구성된 코퍼스에서 0 finding**.

### 기록된 측정

| 일자 (2026) | 대상 | 결과 | 조치 |
|---|---|---|---|
| 10-05 | 합성 클린 코퍼스 (Java Spring/Node Express/Python Flask/Go http, 파라미터화 쿼리·상수 exec·상수 innerHTML 포함) | 최초 측정 **4 오탐** (go 파라미터화 쿼리 CRITICAL, innerHTML 상수 HIGH, 상수 exec HIGH, System.out INFO) | 엔진 placeholder 인식 추가, innerHTML/runtime-exec 룰 정규식 수정, java xss sink 축소, `System.out.println` INFO는 KISA 기준상 유지(설계상 허용) |
| 10-05 | 동일 코퍼스 | **오탐 0건** — 보고된 2건은 (1) 동일 코퍼스에 심어둔 `@RequestParam` SQLi 실제 취약점(신규 param-annotations 소스로 탐지된 TP)과 (2) 설계상 유지된 `System.out.println` INFO 1건뿐 | 재측정 불요 |

항목별 검증 결과 (2026-10-05 실측):
- 파라미터화 쿼리 `db.Query("... ?", id)`: CRITICAL → **미보고**
- 상수 `innerHTML = "..."`: HIGH → **미보고**
- 상수 `exec("df -h")`: HIGH → **미보고**
- `.tsx` 스캔: 항상 degraded(exit 3) → **클린 파싱**
- `--changed` untracked 신규 파일: 0파일 → **탐지**
- baseline + 라인 이동 10줄: `1 new, 1 fixed` → **1 existing, 0 new**
