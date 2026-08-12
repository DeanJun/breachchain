# breachchain

시나리오 기반 침해 진단(모의침투테스트) 자동화 도구. 통신사 보안 진단 포지션 지원용 포트폴리오 프로젝트.

> 다른 PC / 새 Claude Code 세션에서 이 문서만 읽고 바로 이어서 작업할 수 있도록, 배경·설계 결정·현재 상태·다음 단계를 상세히 기록한다. 대화 히스토리가 없어도 이 파일 하나로 전체 맥락을 파악할 수 있어야 한다.

---

## 1. 프로젝트 배경 (왜 만들었는가)

통신사 보안 진단(모의침투테스트) 포지션 지원 목적. JD 핵심 요구사항:
- 시나리오 기반 보안 진단 기획/수행, 진단 절차 자동화
- IoT 단말 보안 진단, 내부망 접근 경로/확산 가능성 진단
- MITRE ATT&CK 기반 시나리오 설계 능력

이 역량을 증명할 기존 프로젝트가 없어서, 직접 시나리오 기반 진단 자동화 도구를 만들어 실행 로그·리포트 산출물로 근거를 남기기로 했다.

**핵심 컨셉**: IoT 단말을 시작 지점으로 삼아, 공개된 검증 절차 라이브러리(Atomic Red Team)를 실행 기반으로 활용하면서, 상태(확보한 자산/자격정보/권한 수준)를 누적하며 진단 범위를 넓혀가는 시나리오를 재현하고, 전체 절차를 MITRE ATT&CK 체계로 매핑/리포팅한다.

**개발 원칙**: 검증 절차 자체(수백~수천 개)는 새로 만들지 않는다. Atomic Red Team이 공개한 절차 정의를 실행 라이브러리로 쓰고, 직접 구현하는 것은 오케스트레이션 레이어(로더, 실행기, 상태 관리, 매핑/리포트)뿐이다. 실무 진단 자동화 도구(Caldera 등)와 동일한 구조.

---

## 2. 저장소 구조

```
breachchain/
├── definitions/          # 손수 작성한 8개 절차 정의 (ART 스키마 참고, 데모 시나리오 전용)
├── scripts/
│   └── fetch_atomics.sh  # 실제 ART 저장소의 atomics/ 폴더만 받아오는 스크립트
├── src/breachchain/
│   ├── loader.py          # definitions/*.yaml 파서 (직접 작성한 단순 스키마)
│   ├── executor.py        # local/SSH 실행기, Windows 셸 해석 안정화 포함
│   ├── state.py            # 상태 누적 (assets/credentials/access, 단순 JSON 구조)
│   ├── mapping.py          # 실행 로그 → ATT&CK 커버리지 레이어
│   ├── report.py            # HTML 리포트 렌더러 (한국어, 흰 배경 고정)
│   ├── scenario.py          # 5단계 데모 시나리오 오케스트레이터 (진입점)
│   ├── cli.py                # 절차 1개만 수동 실행하는 CLI
│   └── art_loader.py         # 실제 ART YAML 스키마 파서 + 안전 필터 + 커버리지 통계
├── vendor/                # gitignore 대상. fetch_atomics.sh로 받는 실제 ART 데이터 (350MB+)
├── runs/                  # gitignore 대상(.json/.jsonl). state.json, coverage.json, art_safe_candidates.json
├── reports/               # gitignore 대상. report_YYMMDD_hhmmss.html
├── logs/                  # gitignore 대상. log_YYMMDD_hhmmss.log (report와 타임스탬프 동일)
└── pyproject.toml
```

**definitions/ vs art_loader.py 차이 — 반드시 구분할 것**:
- `definitions/*.yaml` (8개): 내가 ART 스키마를 참고해서 **직접 작성**한 절차. 데모 시나리오(`scenario.py`)가 쓰는 건 이것뿐이다.
- `vendor/atomic-red-team/atomics/` (fetch로 받는 실제 데이터, 1786개 atomic_tests): 진짜 ART 저장소 원본. `art_loader.py`가 파싱/필터링만 하고, 아직 `scenario.py` 오케스트레이터에는 연결 안 됨(다음 단계).

---

## 3. 셋업 (다른 PC에서 처음 시작할 때)

```bash
git clone https://github.com/DeanJun/breachchain.git
cd breachchain
pip install -e .

# 실제 ART 데이터가 필요할 때만 (art_loader.py 쓸 때)
sh scripts/fetch_atomics.sh
python -m breachchain.art_loader   # 파싱+필터링, runs/art_safe_candidates.json 생성
```

`vendor/`는 git에 없다 (350MB, 서드파티 저장소라 커밋 안 함 — 이유는 5장 참고). `fetch_atomics.sh`가 `git clone --filter=blob:none --sparse`로 `atomics/` 폴더만 받아온다.

## 4. 실행 방법

```bash
python -m breachchain.scenario
```

또는 VSCode에서 `src/breachchain/scenario.py`를 열고 Run(▷). (다른 파일을 열고 실행하면 아무 동작 안 함 — 라이브러리 모듈이라 `scenario.py`만 진입점.)

실행하면:
- 콘솔에 한국어 로그 출력 + `logs/log_YYMMDD_hhmmss.log`에 동일 내용 저장
- `reports/report_YYMMDD_hhmmss.html` 생성 (리포트와 로그는 같은 타임스탬프 공유)
- `runs/state.json`, `runs/coverage.json` 갱신
- 종료 후 Enter 누를 때까지 콘솔 창 유지 (더블클릭 실행 대응)

단일 절차만 테스트: `python -m breachchain.cli --technique T1552.001 --dry-run`

---

## 5. 설계 결정과 이유 (검토 후 제외한 대안 포함)

### 5.1 진단 수준 구분
- 취약점 진단(스캐너) < 정형화된 진단(단일 자산 스코프) < **시나리오 기반 진단(목표 지향, 권한 변화·접근 확대 포함)**
- JD의 "시나리오 기반", "내부 접근 경로/확산 가능성 진단"은 세 번째 수준 → 이 프로젝트의 방향

### 5.2 MITRE ATT&CK과의 정합성
ATT&CK의 Tactic 순서(Initial Access → ... → Impact)가 진단 시나리오의 단계 구조와 동일. 참고 자료가 아니라 도구의 뼈대로 사용.

### 5.3 검토 후 제외한 방향
| 방향 | 제외 이유 |
|---|---|
| 탐지 검증 중심 도구 | 진단/재현 요구보다 탐지 검증에 치우침 |
| 보안대회 문제 재활용 | 초기 접근 위주라 이 프로젝트의 사후 단계와 전제가 다름 |
| IoT 펌웨어 진단 단독 구현 | 정적 분석만으로 "접근 경로/확산" 요구 미충족 |
| 프레임워크 항목 클릭형 리포트 도구 | MITRE 공식 Attack Flow Builder와 기능 중복 |
| ART 전체 절차 직접 재구현 | 개인 프로젝트로 불가능한 범위 → ART 원본을 실행 라이브러리로 활용하는 쪽으로 결정 |

### 5.4 vendor/(ART 원본)를 git에 커밋하지 않는 이유
1. GitHub는 파일 100MB 초과 시 push 자체를 거부, repo 1GB 넘으면 성능 저하
2. ART는 독립 프로젝트(자체 라이선스·히스토리) — 통째로 우리 커밋에 섞으면 안 됨
3. fetch 스크립트 방식이어야 최신 버전을 다시 받을 수 있음
4. 포트폴리오 리뷰어가 "내가 만든 코드"와 "가져다 쓴 데이터"를 명확히 구분해서 볼 수 있어야 함
→ node_modules/npm install, terraform init과 같은 원리

### 5.5 MITRE ATT&CK 데이터 접근
- TAXII 2.1 서버: 10분당 10회 제한 → 실사용 부적합, 미채택
- STIX 데이터셋 직접 파싱(`mitreattack-python`): 채택 예정이나 아직 미구현. 지금은 실행 로그의 technique_id를 그대로 집계하는 수준(`mapping.py`)

---

## 6. 현재까지 진행 상황 (체크리스트)

### 완료 — Day 1 (로더/실행기)
- [x] `loader.py`: 손수 작성한 8개 절차 정의 파서, `#{var}` 치환, 플랫폼 필터
- [x] `executor.py`: local/SSH 실행기
- [x] 절차 정의 8개 (T1552.001, T1087.001, T1016, T1078, T1021.004, T1083, T1005, T1070.004)
- [x] `cli.py`: 단일 절차 실행 + JSONL 로그

### 완료 — Day 2 (상태/매핑/리포트)
- [x] `state.py`: 자산/자격정보/접근 누적 (단순 JSON, 그래프 구조 아님 — 최소 범위 결정)
- [x] `mapping.py`: ATT&CK 커버리지 레이어 생성
- [x] `scenario.py`: 5단계 데모 시나리오 (로컬 fixture로 IoT/내부 노드 흉내)
- [x] 전체 체인 1회 완주 검증 (5/5 성공, state.json/coverage.json/report 정상 생성)

### 완료 — Day 3 (리포트 개선/실행 안정성)
- [x] HTML 리포트 (흰 배경 고정, 한국어, print/PDF 대응)
- [x] 리포트·로그 파일명 `_YYMMDD_hhmmss` 타임스탬프 통일, `reports/`·`logs/` 분리 + gitignore
- [x] 콘솔+파일 동시 로깅, Windows UTF-8 강제(한글 깨짐 수정)
- [x] Windows 실행 버그 수정 모음:
  - subprocess 로케일 디코딩 오류 (cp949) → UTF-8 강제
  - Windows 백슬래시 경로가 `sh -c` 안에서 이스케이프로 오인식 → `as_posix()` 강제
  - `sh`/`bash` PATH 탐색이 WSL 런처(`system32\bash.exe`)를 잘못 집는 문제 → Git for Windows 경로 우선 탐색
  - Git shell을 명시 경로로 찾으면 coreutils(`id`,`rm`,`grep`...)가 PATH에 없는 문제 → Git bin 디렉토리 주입
  - 라이브러리 모듈(executor.py 등)을 직접 실행하면 상대 import 깨짐 → 모든 모듈에 `__package__` 체크 fallback 추가
  - 리포트/로그 파일명이 분 단위라 짧은 간격 재실행 시 덮어써짐 → 초 단위로 변경(사용자 확인 후 최종 결정, 밀리초까지는 불필요 판단)
  - VSCode 디버그 콘솔 등 비대화형 stdin에서 종료 대기 `input()`이 크래시 → try/except로 안전 처리

### 완료 — Day 3.5 (실제 ART 데이터 연동, 파싱/필터만)
- [x] `scripts/fetch_atomics.sh`: 실제 ART 저장소 `atomics/`만 sparse-checkout
- [x] `art_loader.py`: 진짜 ART YAML 스키마(`atomic_tests` 다중 배열) 파서 작성 — `loader.py`와 스키마가 다름에 주의
- [x] 안전 필터(`filter_safe_linux`): linux 지원 + sh/bash 실행기 + elevation_required 아님 + 파괴적 명령 패턴(rm -rf /, mkfs, fork bomb 등) 제외
- [x] 실제 결과: **전체 1786개 atomic_tests 중 232개 통과** (고유 기법 332개 중 90개)
- [x] `runs/art_safe_candidates.json`에 필터링 결과 저장 (232개, gitignore 대상)
- [ ] **이 232개를 `scenario.py` 오케스트레이터에 아직 연결 안 함** — 지금 데모는 여전히 손수 작성한 8개 정의만 사용

---

## 7. 남은 작업 (우선순위 순)

1. **상태 기반 분기 로직 (최우선, 핵심 차별점)** — 지금 `scenario.py`는 5단계가 하드코딩된 순서. `requires`/`provides`를 절차 정의에 선언하고, 현재 `state.py`의 assets/credentials/access와 대조해 "지금 실행 가능한 후보"를 계산하는 `eligible_procedures()` 함수가 필요. 후보가 여럿이면 자동 우선순위 시도 또는 사용자 선택. 후보가 없으면 dead-end로 리포트에 기록.
   - 설계 스펙: YAML에 `requires: [credential, "access:user"]`, `provides: [access:user]` 형태로 선언
   - 이 로직이 붙어야 "그냥 스크립트"에서 "진단 자동화 도구"로 넘어감

2. **art_loader.py의 232개 후보를 오케스트레이터에 연결** — 지금은 파싱/필터링만 하고 실행 경로에 안 붙어 있음. 1번의 `requires`/`provides` 스펙을 이 후보들에도 적용해야 함 (현재 ART YAML엔 없는 필드라 추가 매핑 작업 필요)

3. **블라인드 시딩** — 본인이 미리 정답(자격정보 위치 등)을 아는 상태로 테스트하면 "진단 능력"을 증명하지 못한다는 문제의식에서 나온 방향. 별도 시드 스크립트가 무작위로 자격정보/파일 위치를 정하고, 그 결과를 안 본 채로 도구를 실행해 "실제로 탐색해서 찾아냈다"는 서사를 만듦. 미착수.

4. **실제 원격 노드(SSH) 검증** — 지금까지 전부 `mode="local"` 로컬 fixture로만 테스트. 실제 두 노드(IoT 대리/내부망)를 SSH로 연결해 체인을 돌려본 적 없음. 사용자가 WSL+쿠버네티스에 IoT 환경을 구축할 예정 (진행 상태는 사용자 확인 필요). sshd가 뜬 파드면 executor.py가 수정 없이 바로 됨; `kubectl exec` 방식이면 executor에 새 모드 추가 필요.

5. 자동 테스트 코드 (지금까지 전부 수동 스모크 테스트)

## 8. 솔직한 현재 수준 평가

"동작하는 프로토타입이자 개념 증명"이지 "실무 도구"는 아님. 이유:
- 상태 관리가 사실상 장식(위 7-1 미구현) — 다음 행동을 스스로 결정하지 못함
- credential 파싱 정규식이 매우 취약 (`scenario.py`의 `CRED_PATTERN`)
- 에러 처리/재시도 정책 없음
- `#{var}` 치환이 셸 커맨드에 그대로 삽입됨 — 여러 사람이 쓰는 도구라면 인젝션 검토 필요
- 검증 환경이 로컬 fixture뿐, 실제 네트워크 세그멘테이션/권한 상승 요소 없음

포트폴리오 서사로는 "확장 가능한 프로토타입"으로 정직하게 포지셔닝하는 게 맞고, 인터뷰에서 "실무 수준으로 가려면 뭐가 더 필요한가"라는 질문에 위 목록으로 답할 준비를 해둘 것.

---

## 9. 커밋 히스토리 참고

- `8ad9804` Day 1: definition loader, executor, and 8 scenario procedures
- `3bd3807` Day 2: state accumulation, ATT&CK mapping, HTML report, demo scenario
- `64aaa6b` Day 3: HTML report, console+file logging, Windows run robustness
- (다음 커밋: art_loader.py + fetch_atomics.sh + 이 README)
