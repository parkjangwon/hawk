# korea-secure-coding Rule Pack

행정안전부·한국인터넷진흥원(KISA)이 배포하는 **소프트웨어 개발보안 가이드
(2021.12.29)**와 **자바스크립트 시큐어코딩 가이드(2023년 개정본)**, **파이썬 시큐어코딩
가이드(2023년 개정본)**의 구현단계 보안약점 제거 기준에 매핑된 Hawk 규칙 팩입니다.

Hawk 규칙은 독립적인 ID를 사용하며, 아래 표의 항목 코드(가-1, 나-4 등)는 해당
가이드의 보안약점 항목을 **참조 매핑**한 것입니다. 정부·산업 표준 매핑이 Hawk의
인증·보증·공식 연계를 의미하지는 않습니다.

## Rules

### 가. 입력데이터 검증 및 표현

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.java.sql-injection` (java pack) | 가-1 SQL 삽입 | critical | CWE-89 / A03 |
| `korea.java.code-injection` | 가-2 코드 삽입 | critical | CWE-94 / A03 |
| `korea.java.path-traversal` (java pack) | 가-3 경로 조작 및 자원 삽입 | high | CWE-22 / A01 |
| `korea.java.xss` (java pack) | 가-4 크로스사이트 스크립트 | high | CWE-79 / A03 |
| `korea.java.command-injection` (java pack) | 가-5 운영체제 명령어 삽입 | critical | CWE-78 / A03 |
| `korea.java.open-redirect` | 가-7 신뢰되지 않는 URL 자동접속 | medium | CWE-601 / A01 |
| `korea.java.xxe` | 가-8 부적절한 XML 외부개체 참조 | high | CWE-611 / A05 |
| `korea.java.ldap-injection` | 가-10 LDAP 삽입 | high | CWE-90 / A03 |
| `korea.java.ssrf` (java pack) | 가-12 서버사이드 요청 위조 | high | CWE-918 / A10 |
| `korea.java.http-response-splitting` | 가-13 HTTP 응답분할 | high | CWE-113 / A03 |

### 나. 보안기능

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.java.weak-crypto-algorithm` | 나-4 취약한 암호화 알고리즘 사용 | high | CWE-327 / A02 |
| `korea.java.hardcoded-key` | 나-6 하드코드된 중요정보(암호키) | high | CWE-321 / A02 |
| `korea.java.hardcoded-password` | 나-6 하드코드된 중요정보(비밀번호) | high | CWE-798 / A07 |
| `korea.java.short-crypto-key` | 나-7 충분하지 않은 키 길이 사용 | medium | CWE-326 / A02 |
| `korea.java.weak-random` | 나-8 적절하지 않은 난수값 사용 | medium | CWE-330 / A02 |
| `korea.java.weak-signature` | 나-10 부적절한 전자서명 확인 | high | CWE-347 / A02 |
| `korea.java.insecure-certificate-validation` | 나-11 부적절한 인증서 유효성 검증 | critical | CWE-295 / A02 |
| `korea.java.comment-sensitive-info` | 나-13 주석문 안의 시스템 주요정보 | medium | CWE-615 / A07 |
| `korea.java.unsigned-code-download` | 나-15 무결성 검사 없는 코드 다운로드 | high | CWE-494 / A08 |

### 다. 시간 및 상태 / 라. 에러처리

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.java.toctou` | 다-1 경쟁조건(TOCTOU) | medium | CWE-367 / A04 |
| `korea.java.infinite-loop` | 다-2 종료되지 않는 반복문·재귀 | medium | CWE-835 / A04 |
| `korea.java.stacktrace-public` | 라-1 오류 메시지 정보노출 | medium | CWE-209 / A01 |
| `korea.java.improper-exception` | 라-3 부적절한 예외 처리 | low | CWE-390 / A04 |

### 마. 코드오류 / 바. 캡슐화 / 사. API 오용

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.java.unsafe-deserialization` | 마-5 신뢰할 수 없는 데이터의 역직렬화 | critical | CWE-502 / A08 |
| `korea.java.debug-code` | 바-2 제거되지 않고 남은 디버그 코드 | info | CWE-489 / A04 |
| `korea.java.unsafe-api` | 사-2 취약한 API 사용 | medium | CWE-676 / A04 |
| `korea.java.raw-socket` | 사-2 취약한 API 사용(직접 소켓) | medium | CWE-676 / A04 |

> `(java pack)` 표시 항목은 동일 탐지 로직이 `java` 팩에 먼저 존재하는
> 매핑 항목입니다(중복 탐지를 피하기 위해 korea 팩에 중복 정의하지 않음).


## JavaScript Rules (Javascript 시큐어코딩 가이드, 2023년 개정본)

동일 배포처의 **자바스크립트 시큐어코딩 가이드(2023년 개정본)** 구현단계 보안약점
항목에 매핑된 규칙입니다. taint 규칙(가-1, 가-4 XSS 등)은 변수·함수 흐름을
추적하는 데이터플로우 엔진(JS/Python 지원)을 사용합니다.

### 가. 입력데이터 검증 및 표현

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.js.sql-injection` | 가-1 SQL 삽입 | critical | CWE-89 / A03 |
| `korea.js.code-injection` (js pack: `javascript.security.eval`) | 가-2 코드 삽입 | critical | CWE-95 / A03 |
| `korea.js.path-traversal` | 가-3 경로 조작 및 자원 삽입 | high | CWE-22 / A01 |
| `korea.js.xss` | 가-4 크로스사이트 스크립트(DOM sink taint 추적) | high | CWE-79 / A03 |
| `korea.js.xss-react` | 가-4 크로스사이트 스크립트(React dangerouslySetInnerHTML) | high | CWE-79 / A03 |
| `korea.js.command-injection` | 가-5 운영체제 명령어 삽입 | critical | CWE-78 / A03 |
| `korea.js.open-redirect` (js pack: `javascript.security.open-redirect`) | 가-7 신뢰되지 않는 URL 자동접속 | medium | CWE-601 / A01 |
| `korea.js.xxe` | 가-8 부적절한 XML 외부 개체 참조 | high | CWE-611 / A05 |
| `korea.js.ldap-injection` | 가-10 LDAP 삽입 | high | CWE-90 / A03 |
| `korea.js.ssrf` | 가-12 서버사이드 요청 위조 | high | CWE-918 / A10 |

### 나. 보안기능 / 다. 시간 및 상태 / 라. 에러처리 / 바. 캡슐화

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.js.weak-crypto` | 나-4 취약한 암호화 알고리즘 사용 | high | CWE-327 / A02 |
| `korea.js.weak-random` | 나-8 적절하지 않은 난수 값 사용 | medium | CWE-330 / A02 |
| `korea.js.infinite-loop` | 다-1 종료되지 않는 반복문·재귀 | medium | CWE-835 / A04 |
| `korea.js.error-message-info` | 라-1 오류 메시지 정보노출 | medium | CWE-209 / A01 |
| `korea.js.improper-exception` | 라-3 부적절한 예외 처리 | low | CWE-390 / A04 |
| `korea.js.debug-code` | 바-2 제거되지 않고 남은 디버그 코드 | info | CWE-489 / A04 |

> 가-2(eval), 가-7(open redirect), 가-4(innerHTML/document.write)는 `js` 팩의
> 기존 규칙이 동일 탐지를 수행하므로 매핑만 표기하고 중복 정의하지 않았습니다.


## Python Rules (Python 시큐어코딩 가이드, 2023년 개정본)

동일 배포처의 **파이썬 시큐어코딩 가이드(2023년 개정본)** 구현단계 보안약점
항목에 매핑된 규칙입니다. taint 규칙은 JS와 동일한 데이터플로우 엔진을
사용합니다.

### 가. 입력데이터 검증 및 표현

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.py.sql-injection` | 가-1 SQL 삽입 | critical | CWE-89 / A03 |
| `korea.py.code-injection` (python pack: `python.security.eval-exec`) | 가-2 코드 삽입 | critical | CWE-95 / A03 |
| `korea.py.path-traversal` | 가-3 경로 조작 및 자원 삽입 | high | CWE-22 / A01 |
| `korea.py.xss` | 가-4 크로스사이트 스크립트(mark_safe·HttpResponse taint 추적) | high | CWE-79 / A03 |
| `korea.py.command-injection` (python pack: `python.security.os-system`, `subprocess-shell`) | 가-5 운영체제 명령어 삽입 | high | CWE-78 / A03 |
| `korea.py.xxe` | 가-8 부적절한 XML 외부 개체 참조 | high | CWE-611 / A05 |
| `korea.py.ssrf` (python pack: `python.security.ssrf`) | 가-12 서버사이드 요청 위조 | high | CWE-918 / A10 |

### 나. 보안기능 / 다. 시간 및 상태 / 라. 에러처리 / 마. 코드오류 / 바. 캡슐화

| Rule id | 항목 | Severity | CWE / OWASP |
|---------|------|----------|-------------|
| `korea.py.weak-crypto` | 나-4 취약한 암호화 알고리즘 사용 | high | CWE-327 / A02 |
| `korea.py.weak-random` | 나-8 적절하지 않은 난수 값 사용 | medium | CWE-330 / A02 |
| `korea.py.toctou` | 다-1 경쟁조건(TOCTOU) | medium | CWE-367 / A04 |
| `korea.py.infinite-loop` | 다-2 종료되지 않는 반복문·재귀 | medium | CWE-835 / A04 |
| `korea.py.error-message-info` | 라-1 오류 메시지 정보노출 | medium | CWE-209 / A01 |
| `korea.py.improper-exception` | 라-3 부적절한 예외 처리 | low | CWE-390 / A04 |
| `korea.py.unsafe-deserialization` | 마-3 신뢰할 수 없는 데이터의 역직렬화 | critical | CWE-502 / A08 |
| `korea.py.debug-code` | 바-2 제거되지 않고 남은 디버그 코드 | info | CWE-489 / A04 |

> 가-2(eval/exec), 가-5(os.system/subprocess), 가-12(requests), 마-3(pickle)은
> `python` 팩의 기존 규칙이 동일 탐지를 수행하므로 매핑만 표기하고 중복 정의하지
> 않았습니다.

## Limitations

- 가-6 파일 업로드, 가-11 CSRF, 나-5 평문 저장 등은 정적 탐지가 어려워 미구현입니다.
- JS·Python XSS(가-4)는 데이터플로우(taint) 기반으로 탐지합니다(Java도 동일).
  JS는 아직 범용 데이터플로우가 아니라 소스→변수→sink 추적 수준이며, Python은
  추가 엔진 확장이 필요합니다.
- `open()` 비리터럴 경로, `print()` 등은 휴리스틱 패턴으로 오탐 가능성이 있으며,
  info/low 심각도로 완화했습니다.

## Limitations

- JS 데이터플로우(taint) 엔진 미지원으로 JS 규칙은 패턴 기반입니다.
- 가-6 파일 업로드, 가-11 CSRF, 나-5 평문 저장 등은 정적 탐지가 어려워 미구현입니다.

## Limitations

- 가이드의 모든 항목이 정적 패턴으로 탐지 가능한 것은 아닙니다(가-6 파일 업로드,
  가-11 CSRF, 나-5 중요정보 평문 저장, 나-14 솔트 없는 해시 등은 설계·런타임
  판단이 필요하여 미구현).
- Regex·휴리스틱 taint 기반이며, 정밀도(오탐 억제)를 우선합니다.
- Java 중심이며, `comment-sensitive-info`는 다중 언어를 지원합니다.