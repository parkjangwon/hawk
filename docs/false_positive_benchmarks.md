# Hawk 룰 오탐률(False Positive) 측정 체계 및 벤치마크

정적 분석 도구의 실효성은 미탐(False Negative) 방지뿐만 아니라 **오탐(False Positive) 억제**에 의해 결정됩니다. 과도한 오탐은 개발자의 경고 피로를 유발하여 도구의 신뢰성을 떨어뜨립니다.

Hawk은 **결정론적 픽스처(Deterministic Fixtures)** 체계와 **다계층 필터링(Multi-tier Filtering)**을 통해 룰별 오탐률을 정량적으로 측정하고 0%에 가깝게 유지합니다.

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
- 이를 통해 신규 룰 추가 및 기존 룰 수정 시 오탐 회귀를 100% 방지합니다.

### 1.2 엔진 레벨의 오탐 억제 기술
Hawk은 단순한 정규표현식 매칭에 의존하지 않고 다음 기술로 오탐을 차단합니다:

1. **`not_regex` 네거티브 필터링**:
   - 더미 데이터(`placeholder`, `dummy`, `test`, `example`)나 안전한 상수 리터럴이 포함된 패턴을 자동 배제.
2. **Tree-sitter AST & Predicate 평가**:
   - 정적 텍스트 매칭 대신 문법 노드(`method_invocation`, `call_expression`)를 식별하고, 인자 형태(`anchor`, `#not-match?`)를 검사.
3. **데이터 흐름 & 새니타이저(Sanitizer) 추적**:
   - `taint` 엔진에서 이스케이프 함수나 유효성 검증기를 거친 변수는 taint 상태를 정화하여 오탐 보고를 차단.

---

## 2. 언어별 룰 팩 오탐률 벤치마크 현황

| 룰 팩 (`pack`) | 룰 수 | 검증된 안전 픽스처 수 | 오탐 검증 상태 | 주요 방어 메커니즘 |
|---|---|---|---|---|
| **korea** | 51 | 51개 이상 | ✅ 0건 (Pass) | 공공기관 KISA 개발보안 가이드 안전/취약 예제 1:1 매핑 |
| **java** | 9 | 15개 이상 | ✅ 0건 (Pass) | Spring Framework/Java 표준 클래스 인식, Taint Sanitizer |
| **python** | 9 | 12개 이상 | ✅ 0건 (Pass) | SafeLoader 구별, hash알고리즘 분기, 더미 시크릿 배제 |
| **js** | 8 | 10개 이상 | ✅ 0건 (Pass) | React DOM API 인식, crypto 메서드 인자 정밀 매칭 |
| **go** | 6 | 8개 이상 | ✅ 0건 (Pass) | 표준 라이브러리 `crypto/*`, `os.*` 호출 시그니처 검사 |

---

## 3. 대표 오픈소스 검증 가이드라인

신규 룰 개발 시 다음 표준 오픈소스 레포지토리의 소스를 대상으로 스캔하여 오탐 빈도를 측정합니다:

- **Java**: Spring PetClinic, WebGoat
- **Python**: Django Girls Tutorial, Flaskr, OWASP Juice Shop (백엔드)
- **JS/TS**: Express Starter, RealWorld Example App
- **Go**: Gin Examples, Kubernetes client-go 샘플

측정 방법:
```bash
hawk --pack <pack-name> /path/to/repo --format json -o audit-report.json
```
리포트 내의 모든 finding을 수동 검토하여 오탐으로 판명된 패턴은 해당 룰의 `not_regex` 또는 AST 쿼리 anchor로 정밀화합니다.
