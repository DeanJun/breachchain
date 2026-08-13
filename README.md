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
├── scripts/
│   └── fetch_atomics.sh  # 실제 ART 저장소의 atomics/ 폴더만 받아오는 스크립트
├── src/breachchain/
│   ├── art_loader.py      # 실제 ART YAML 스키마 파서 + 안전 필터 + candidates json 로더/조회
│   ├── executor.py        # local/SSH 실행기 (AtomicTest 대상), paramiko 기반 (키+비밀번호 인증), 접속 사전 체크
│   ├── state.py            # 상태 누적 (assets/credentials/access, 단순 JSON 구조)
│   ├── mapping.py          # 실행 로그 → ATT&CK 커버리지 레이어
│   ├── tactic_mapping.py     # technique_id → tactic 매핑 (mitreattack-python, STIX 데이터셋)
│   ├── recon.py               # IP만으로 하는 정찰: 포트 스캔 (nmap 있으면 사용, 없으면 순수 파이썬 소켓 스캔), HTTP Server 헤더 배너
│   ├── web_recon.py            # HTTP 경로/디렉토리 브루트포싱 (숨겨진 admin/backup/.git 등 탐색)
│   ├── vuln_scan.py             # 배너 버전 → NVD CVE 매칭 (휴리스틱, 재현율 낮음 — 아래 5.6 참고)
│   ├── bruteforce.py             # SSH 계정/비밀번호 무차별 대입 (초기 접근용)
│   ├── kisa_runner.py             # KISA CIIP 2026 기술적 취약점 진단 스크립트를 원격 SSH 대상에 업로드+실행 (아래 5.7 참고)
│   ├── report.py                   # HTML 리포트 렌더러 (한국어, 흰 배경 고정; 정찰/브루트포싱/CVE/KISA/전술별 섹션 포함)
│   ├── cli.py                       # ART 후보 1개만 수동 실행하는 CLI (--dry-run, --check-only 지원)
│   ├── art_runner.py                 # ART 후보 여러 개를 배치 실행 (+ --by-tactic로 전술 순서 실행) + state/coverage/report 산출
│   └── pipeline.py                    # 메인 진입점: IP만 주면 정찰→CVE매칭→(브루트포싱)→KISA 진단→전술별 ART 실행→통합 리포트
├── vendor/                # gitignore 대상.
│   ├── atomic-red-team/   # fetch_atomics.sh로 받는 실제 ART 데이터 (350MB+)
│   ├── mitre-attack/      # tactic_mapping.py --fetch로 받는 STIX 데이터셋 (~54MB)
│   └── kisa-ciip/         # git clone https://github.com/rebugui/KISA-CIIP-2026.git (아래 5.7 참고)
├── runs/                  # gitignore 대상(.json/.jsonl). state.json, coverage.json, art_safe_candidates.json, recon/bruteforce/web_recon/vuln_scan/kisa_results.json
├── reports/               # gitignore 대상. report_YYMMDD_hhmmss.html
├── logs/                  # gitignore 대상. log_YYMMDD_hhmmss.log (report와 타임스탬프 동일)
└── pyproject.toml
```

**2026-08-13: 손수 작성한 데모(definitions/ 8개, loader.py, scenario.py) 전부 삭제.** 파이프라인 검증용으로만 쓰던 하드코딩 5단계 체인이라 필요 없어짐 — 지금부터는 실제 ART 데이터(`vendor/atomic-red-team/atomics/` → `art_loader.py` 파싱/필터 → `runs/art_safe_candidates.json`)만 실행 대상으로 쓴다. `executor.py`의 `execute()`/`command_preview()`도 `AtomicTest`만 받도록 정리했다 (예전엔 손수 작성 스키마용 `ProcedureDef`도 같이 받았음).

---

## 3. 셋업 (다른 PC에서 처음 시작할 때)

```bash
git clone https://github.com/DeanJun/breachchain.git
cd breachchain
pip install -e ".[mapping]"   # mitreattack-python 포함 (tactic 매핑에 필요)

# 실제 ART 데이터가 필요할 때만 (art_loader.py 쓸 때)
sh scripts/fetch_atomics.sh
python -m breachchain.art_loader   # 파싱+필터링, runs/art_safe_candidates.json 생성

# tactic 매핑이 필요할 때만 (tactic_mapping.py 쓸 때)
python -m breachchain.tactic_mapping --fetch   # vendor/mitre-attack/enterprise-attack.json 다운로드 (~54MB)
python -m breachchain.tactic_mapping           # 파싱, runs/tactic_mapping.json 생성

# KISA CIIP 진단이 필요할 때만 (kisa_runner.py 쓸 때)
git clone https://github.com/rebugui/KISA-CIIP-2026.git vendor/kisa-ciip
```

`vendor/`는 git에 없다 (350MB, 서드파티 저장소라 커밋 안 함 — 이유는 5장 참고). `fetch_atomics.sh`가 `git clone --filter=blob:none --sparse`로 `atomics/` 폴더만 받아온다. `enterprise-attack.json`(STIX 데이터셋, ~54MB)도 같은 이유로 git에 없고 `tactic_mapping.py --fetch`로 받는다. `vendor/kisa-ciip/`(6.7MB, 스크립트라 작음)도 같은 원칙으로 git에 안 넣고 clone으로 받는다.

## 4. 실행 방법

### 4.0 전체 파이프라인 (IP만 주고 시작 — 권장 진입점)
```bash
# 자격정보 모르는 상태: 정찰 -> CVE 매칭 -> SSH 브루트포싱 -> 뚫리면 KISA 진단 + 전술별 ART 실행 -> 통합 리포트
python -m breachchain.pipeline 10.0.0.5

# 계정을 이미 아는 상태: 브루트포싱 생략하고 바로 진단
python -m breachchain.pipeline 10.0.0.5 --user pentest --password '...'
python -m breachchain.pipeline 10.0.0.5 --user pentest --key ~/.ssh/id_rsa

# 각 단계 생략 가능
python -m breachchain.pipeline 10.0.0.5 --skip-recon --skip-vuln-scan --skip-kisa --user pentest --password '...'

# 인자 없이 실행하면 대화형으로 IP/계정을 물어봄 (VSCode F5, 더블클릭 실행 등 터미널 없이 실행할 때 대비)
python -m breachchain.pipeline
```
기본 `--limit 20`(ART 후보 20개까지만), `--limit 0`이면 233개 전체. KISA CIIP 진단은 기본 Debian 플랫폼(Ubuntu와 호환), `--kisa-platform RedHat` 등으로 변경 가능. 결과는 다른 진입점과 동일하게 `reports/`·`logs/`·`runs/`에 쌓이고, 리포트 하나에 **열린 포트**·**CVE 매칭**·**브루트포싱으로 찾은 자격정보**·**KISA CIIP 67개 항목 진단(양호/취약/수동)**·**전술별로 묶인 ART 실행 결과**가 전부 들어간다.

### 4.1 정찰/브루트포싱/웹스캔/CVE매칭/KISA진단 — 각각 따로
```bash
python -m breachchain.recon 10.0.0.5                          # 포트 스캔만, runs/recon.json
python -m breachchain.bruteforce 10.0.0.5 --port 22            # SSH 브루트포싱만, runs/bruteforce.json
python -m breachchain.web_recon http://10.0.0.5:80              # 웹 경로 스캔만, runs/web_recon.json
python -m breachchain.vuln_scan                                  # runs/recon.json 배너로 CVE 매칭, runs/vuln_scan.json
python -m breachchain.kisa_runner 10.0.0.5 --user pentest --password '...'   # KISA CIIP 진단만, runs/kisa_results.json
```

### 4.2 절차 1개만 (기법 하나 지정, 필요시 `--guid`로 후보 여러 개 중 선택)
```bash
python -m breachchain.cli --technique T1005 --dry-run   # 실행할 명령만 미리보기
python -m breachchain.cli --technique T1005              # 실제 실행 (기본 mode=local)
python -m breachchain.cli --technique T1005 --mode ssh --host 10.0.0.5 --user pentest --key ~/.ssh/id_rsa
python -m breachchain.cli --technique T1005 --mode ssh --host 10.0.0.5 --user pentest --password '...'
```

### 4.3 여러 절차를 배치로 (기본 `--limit 10`, `--limit 0`은 233개 전체)
```bash
python -m breachchain.art_runner --limit 5
python -m breachchain.art_runner --technique T1005 --technique T1083 --mode ssh --host 10.0.0.5 --user pentest
python -m breachchain.art_runner --limit 30 --by-tactic --mode ssh --host 10.0.0.5 --user pentest --password '...'  # 전술 순서로 실행
```

`art_runner` 실행하면:
- 콘솔에 한국어 로그 출력 + `logs/log_YYMMDD_hhmmss.log`에 동일 내용 저장
- `reports/report_YYMMDD_hhmmss.html` 생성 (리포트와 로그는 같은 타임스탬프 공유)
- `runs/state.json`(실행 이력만 기록 — 아래 6.5/7-1 참고), `runs/coverage.json` 갱신

둘 다 `runs/art_safe_candidates.json`이 미리 있어야 함(3장 셋업 참고).

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
- STIX 데이터셋 직접 파싱(`mitreattack-python`): **2026-08-13 구현** (`tactic_mapping.py`). `enterprise-attack.json`을 로컬에 받아 `MitreAttackData.get_tactics_by_technique()`로 technique_id → tactic 목록을 뽑는다. 실행 로그 집계(`mapping.py`)는 여전히 그대로 유지 — 이건 별도 관심사(수집된 tactic 매핑 vs 실행 결과 커버리지).
- **주의**: 이 STIX 데이터셋이 최신 ATT&CK v18 개편을 반영하고 있어, 예전에 익숙한 "Defense Evasion" 전술이 없고 대신 **"Defense Impairment"**와 **"Stealth"**로 나뉘어 있다. 총 15개 전술(Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Impairment, Stealth, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact). 인터뷰 등에서 "Defense Evasion"으로 알고 있는 사람과 얘기할 때 이 개편 사실을 언급할 것.

### 5.6 vuln_scan.py의 한계 (정직하게 밝혀둘 것)
NVD `keywordSearch`는 CVE **설명 텍스트에 대한 자유텍스트 검색**이라, "제품명 + 정확한 버전 문자열"을 넣어도 그 문자열이 CVE 설명에 그대로 안 적혀있으면 못 찾는다. CVE 설명은 보통 "product before X.Y" 같은 **버전 범위**로 적혀있다. 그래서:
- OpenSSH 7.4(오래된 버전, 딱 "before 7.4"로 여러 CVE에 언급됨)로 테스트하면 CVE-2016-10009 등 6건 정상적으로 잡힘 → 메커니즘 자체는 검증됨
- 실제 VM의 OpenSSH 8.9p1, nginx 1.18.0(둘 다 실제로 알려진 CVE가 있을 가능성이 있는 버전)은 **키워드 매칭 실패로 0건**
- 즉 지금 구현은 "재현율이 낮은 휴리스틱"이다. 정확하게 하려면 NVD의 CPE 기반 검색(`cpeName` 파라미터, `cpe:2.3:a:vendor:product:version`)으로 바꿔야 하는데, 이건 제품별 정확한 vendor:product CPE 이름 매핑 테이블이 추가로 필요해서 미착수. 리포트에도 이 한계를 명시하는 문구를 넣어뒀다.

### 5.7 KISA CIIP 2026 진단 스크립트 통합 (`kisa_runner.py`)
**계기**: "브루트포싱/ART로 계정을 뚫었는데, 뚫은 것 자체 말고 서버 안에 또 뭐가 위험한지는 어떻게 아나?"라는 질문에서 시작. ART는 "이 공격 기법이 재현되는가"를 보고, `vuln_scan.py`는 "배너 버전에 알려진 CVE가 있는가"를 보는데, 둘 다 **"이 서버의 설정 자체가 KISA 기준으로 안전한가"**는 답하지 못함. 그래서 국내 표준(KISA 주요정보통신기반시설 기술적 취약점 분석·평가 가이드)에 맞춰 이미 완성돼 있는 공개 진단 스크립트 저장소([rebugui/KISA-CIIP-2026](https://github.com/rebugui/KISA-CIIP-2026), AGPL-3.0)를 원격 실행 가능하게 감쌌다.

**검토했던 대안과 기각 이유**:
- KISA 항목을 breachchain에 통째로 새로 짜기 → 이미 완성된 625개 항목(67 Unix + 64 Windows + 78 웹서버 + 26 IIS + 104 DBMS + 18 PC)을 재구현하는 건 ART를 재구현 안 하기로 한 결정(5.3절)과 같은 논리로 불필요
- breachchain을 버리고 KISA-CIIP를 포크해서 새 프로젝트로 시작 → 이미 오케스트레이션(Template Method 패턴, 화이트리스트 검증, JSON/TXT 이중 출력)까지 완성된 완제품이라, "튜닝"만 하면 남는 원본 기여가 얇아짐. breachchain의 3일치 검증된 파이프라인(접속확인/로깅/리포트)도 버리게 됨 → 기각
- **채택**: KISA-CIIP를 ART처럼 "실행 라이브러리"로 취급하고, breachchain이 가진 오케스트레이션(SSH 접속, 로깅, 통합 리포트)으로 감싸서 실행

**동작 방식**: KISA 스크립트는 원래 "실행되는 그 컴퓨터 자체"를 진단하도록 설계됨(로컬 전용, 원격 대상 지정 기능 없음). `kisa_runner.py`가 이걸 원격 대상 지정 가능하게 만드는 역할:
1. paramiko SFTP로 `lib/`(공유 함수)와 대상 플랫폼(Debian 등)의 스크립트 디렉토리를 원격 `/tmp/breachchain-kisa-ciip/`에 업로드 (KISA 스크립트가 `../../lib`로 상대 참조하므로 원본과 동일한 2단계 디렉토리 구조를 그대로 복제해야 함)
2. SSH로 `run_all.sh` 원격 실행 (67개 항목 전부, `systemctl`/`grep`/`ps` 등 대상 서버 안에서 직접 실행됨)
3. `run_all.sh`는 통합 결과를 **파일로** 저장하고 그 경로만 stdout에 한 줄 찍는 구조(처음엔 이걸 몰라서 stdout에서 JSON을 직접 파싱하려다 0건 나옴 → 원본 스크립트(`lib/result_manager.sh`)를 읽고서야 파일 저장 방식인 걸 확인). 그 경로를 정규식으로 뽑아서 SFTP로 파일 하나만 받아와 파싱
4. `report.py`에 "KISA CIIP 기술적 취약점 진단" 섹션 추가 (양호/취약/수동진단 집계 + 취약 항목별 조치방법)

**실제 VM(Ubuntu, Debian 플랫폼) 검증 결과**: 67개 중 66개 파싱 성공(1개는 원본 스크립트 자체 버그로 실패, U-64), 양호 46 / 취약 16 / 수동진단 3. 실제로 잡힌 취약 항목 예시: U-01(root 원격 접속 제한 미설정), U-18(`/etc/shadow` 권한 640 — 가이드 기준 부적절), U-25(world-writable 파일 30개), U-37(crontab 파일 권한 644, 600 권장). `pipeline.py`에 자동 연결됨(`--skip-kisa`로 생략 가능), 접속 성공 후 ART 실행 전에 돈다.

**아직 안 된 것**: Debian(Unix 서버)만 지원. 원본 저장소엔 Windows(64개), 웹서버(Apache/Nginx/Tomcat/IIS, 26개×4), DBMS(MySQL/PostgreSQL/Oracle/MSSQL, 26개×4), PC(18개)까지 있는데 아직 연결 안 함 — 지금 테스트 대상이 Ubuntu 서버 하나뿐이라 우선순위에서 밀림. AGPL-3.0이라 이 프로젝트를 배포/서비스화할 경우 라이선스 고지 의무 있음(포트폴리오 공개 저장소로만 쓸 거면 문제 없으나, 나중에 상용화 논의 시 짚어야 함).

---

## 6. 현재까지 진행 상황 (체크리스트)

### 완료 — Day 1 (로더/실행기) — 이후 삭제됨, 아래 참고
- [x] `loader.py`: 손수 작성한 8개 절차 정의 파서, `#{var}` 치환, 플랫폼 필터 → **2026-08-13 삭제**
- [x] `executor.py`: local/SSH 실행기
- [x] 절차 정의 8개 (T1552.001, T1087.001, T1016, T1078, T1021.004, T1083, T1005, T1070.004) → **2026-08-13 삭제**
- [x] `cli.py`: 단일 절차 실행 + JSONL 로그 → 이후 ART 후보 기반으로 재작성 (아래 참고)

### 완료 — Day 2 (상태/매핑/리포트)
- [x] `state.py`: 자산/자격정보/접근 누적 (단순 JSON, 그래프 구조 아님 — 최소 범위 결정)
- [x] `mapping.py`: ATT&CK 커버리지 레이어 생성
- [x] `scenario.py`: 5단계 데모 시나리오 (로컬 fixture로 IoT/내부 노드 흉내) → **2026-08-13 삭제**
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
- [x] **2026-08-13 재수집**: `fetch_atomics.sh`로 ART 원본 재클론 후 안전 필터 재실행. ART 저장소가 소폭 업데이트되어 수치 갱신: 전체 **1801개** atomic_tests(고유 기법 337개) 중 필터 통과 **233개**(고유 기법 91개). 필터 로직 자체 변경은 없음 — 결과가 거의 그대로 재현되어 필터가 안정적으로 동작함을 확인.

### 완료 — Day 4 (하드코딩 데모 제거, ART 후보를 실제 실행 경로에 연결)
- [x] `definitions/`, `loader.py`, `scenario.py` 삭제 — 파이프라인 검증용 하드코딩 5단계 데모였고 더 이상 필요 없음
- [x] `art_loader.py`에 `load_candidates()`(art_safe_candidates.json → `AtomicTest` 역직렬화), `find_candidate()`(technique_id/guid 조회), `AtomicTest.cleanup_command_resolved()` 추가
- [x] `executor.py`: `execute()`/`command_preview()`가 `AtomicTest`를 직접 받도록 정리 (기존 `ProcedureDef` 기반 로직 제거, `execute_atomic`이라는 별도 이름 없이 통합)
- [x] `cli.py`: ART 후보 1개를 technique_id(+선택적 guid)로 찾아 실행/미리보기하는 CLI로 재작성 (`--dry-run`, `--var`로 인자 오버라이드, `--mode local|ssh`)
- [x] `art_runner.py` 신규: 후보 여러 개(`--technique` 필터, `--limit`)를 배치 실행하고 기존 state/coverage/report 파이프라인 그대로 산출
- [x] import/CLI 동작 확인: `python -m breachchain.cli --technique T1005 --dry-run` 정상 (명령 resolve 확인), `art_runner`의 후보 선택 로직(`select_candidates`) 단위 확인. **아직 실제 실행(로컬/SSH)은 하지 않음 — 코드만 준비, 다음 세션에서 대상 정해서 실행 예정**
- [x] `executor.py`에 `check_connection()` 추가 — 실제 절차 실행 전에 SSH 대상에 `echo`를 날려 접속 가능 여부부터 확인. `cli.py`/`art_runner.py` 둘 다 기본으로 이 사전 체크를 거치고 실패하면 중단 (`--skip-check`로 우회 가능, `--check-only`로 접속 테스트만 단독 실행 가능). 로컬(OK)·존재하지 않는 SSH 대상(connection refused로 FAIL)으로 동작 확인

### 완료 — Day 5 (technique_id → tactic 매핑)
- [x] `mitreattack-python` 설치, `enterprise-attack.json`(STIX, official) 다운로드 → `vendor/mitre-attack/` (gitignore 대상)
- [x] `tactic_mapping.py`: `build_technique_tactic_map()`(전체 697개 기법 매핑), `tactics_for()`(하위 기법은 상위 기법으로 폴백), `group_by_tactic()`(candidate 리스트를 tactic별로 묶음, 다중 tactic 기법은 각 tactic에 중복 포함)
- [x] `runs/tactic_mapping.json` 생성 (697개 기법, 매핑 실패 0개)
- [x] 233개 ART 후보 전체(고유 기법 91개)에 tactic 라벨 부여 검증 완료 — 91개 기법 전부 매핑 성공, 미매핑 0개
- [x] **중요 발견**: 이 STIX 데이터셋이 최신 ATT&CK v18 개편을 반영해 "Defense Evasion" 전술이 없고 "Defense Impairment"/"Stealth"로 분리되어 있음 (5.5절 참고)
- [x] **2026-08-13 완료**: `art_runner.py`에 `run_batch_by_tactic()` 추가 — `group_by_tactic()`으로 묶은 후보를 `TACTIC_ORDER`(공식 ATT&CK 전술 순서)대로 순회하며 실행. `--by-tactic` 플래그로 사용. `report.py`도 `step_tactics`를 받아 리포트에 전술 구간 헤더를 표시하도록 확장.

### 완료 — Day 6 (초기 접근: 정찰/브루트포싱, 비밀번호 인증, 전술별 실행 연결, 통합 파이프라인)
- [x] **문제의식**: "IP만 주면 침투 테스트 되냐"는 질문에서 시작. 지금까지 도구는 SSH 계정이 이미 있다고 전제했고, 계정 없이 IP 하나로 시작하는 "진짜 초기 접근" 단계가 아예 없었음.
- [x] `executor.py`: SSH 실행을 `subprocess` + `ssh` CLI에서 **paramiko**로 전환. `BatchMode=yes` 때문에 안 됐던 **비밀번호 인증**을 지원(`Target.password` 필드 추가, 키/비밀번호 둘 다 받음). `cli.py`/`art_runner.py`/`pipeline.py`에 `--password` 옵션 추가.
- [x] `recon.py` 신규: IP만으로 로컬에서 실행하는 포트 스캔. `nmap`이 PATH에 있으면 그걸 쓰고(서비스/버전 탐지), 없으면 순수 파이썬 스레드풀 소켓 커넥트 스캔 + 배너 그래빙으로 폴백. 이 환경엔 nmap이 없어서 소켓 폴백 경로로 동작 확인.
- [x] `bruteforce.py` 신규: SSH 계정/비밀번호 무차별 대입 (기본 계정 7개 x 비밀번호 12개, 스레드풀). 성공한 조합을 `runs/bruteforce.json`에 기록.
- [x] `art_runner.py`에 `run_batch_by_tactic()` 추가 — `tactic_mapping.py`의 `group_by_tactic()`으로 후보를 tactic별로 묶고, `TACTIC_ORDER`(Reconnaissance → ... → Impact, ATT&CK v18 순서)대로 순회하며 실행. `--by-tactic` 플래그.
- [x] `report.py` 확장: `recon`/`bruteforce`/`step_tactics` 파라미터 추가 — 리포트에 "열린 포트" 섹션, "SSH 브루트포싱으로 찾은 자격정보" 섹션, 실행 체인에 전술 구간 헤더(`<h3>전술: Discovery</h3>` 식)를 표시.
- [x] `pipeline.py` 신규 (권장 진입점): `IP 입력 → 정찰(포트 스캔) → 자격정보 없으면 브루트포싱 → 접속 확인 → 전술별 ART 실행 → 통합 리포트`를 한 번에 수행. 자격정보를 못 찾으면 절차 실행 없이 정찰/브루트포싱 결과만 담은 리포트를 내고 종료.
- [x] 단위/런타임 검증: `recon.py`(로컬 소켓 스캔 정상), `bruteforce.py`(연결 거부를 정확히 실패 처리), `report.py`(recon/bruteforce/전술 섹션이 실제 HTML에 렌더링됨), `pipeline.py`(자격정보 없을 때 절차 실행 없이 우아하게 종료, SSH 연결 실패 시 정상 중단) 확인 완료.
- [x] **실행 중 발견한 진짜 버그 수정**: `art_runner --by-tactic --mode local --limit 3` 로컬 검증 중 무한 대기 발생. 원인 두 가지 — (1) `subprocess.run`에 `stdin`을 안 막아놔서 stdin을 읽으려는 ART 명령이 영원히 대기, (2) `subprocess.run(timeout=...)`은 직계 자식만 죽이고, 그 자식이 만든 손자 프로세스(백그라운드 job 등)가 stdout/stderr 파이프를 물고 있으면 타임아웃 이후에도 출력을 읽으려다 무한 대기. `_run_subprocess()`를 `Popen` + 백그라운드 리더 스레드(daemon) 방식으로 재작성해서, 타임아웃 후 `taskkill /F /T`(Windows)로 프로세스 트리를 통째로 죽이고, 리더 스레드는 join에 짧은 캡을 걸어 손자 프로세스가 파이프를 계속 물고 있어도 정해진 시간 안에 항상 리턴하도록 수정. 수정 후 재검증: 3개 후보(Discovery→Collection→Command and Control 전술 순서) 끝까지 실행, 리포트 정상 생성 확인.
- [x] **2026-08-13 실제 VM end-to-end 검증 완료**: VM(Ubuntu, 192.168.94.131) 계정(`ubuntu`) 확보 후 `python -m breachchain.pipeline 192.168.94.131 --user ubuntu --password ... --limit 3` 실행 — 접속 확인 OK, ART 3개 후보 전술 순서(Discovery→Collection→Command and Control)대로 3/3 성공, 리포트 정상 생성. 비밀번호 인증도 이 실행으로 함께 검증됨.
- [ ] **여전히 없는 것 (사용자가 명시적으로 물어봤던 것)**: VM 간 트래픽 가로채기/MITM, 퍼징. ART 라이브러리에 real한 MITM 절차가 없고(프록시가 이미 설정된 걸 전제), 퍼징은 카테고리 자체가 다름(취약점 탐색 vs TTP 재현) — 별도 도구 통합이 필요하며 이번 범위에는 포함 안 함.

### 완료 — Day 7 (외부 정찰 확장 + KISA CIIP 통합 + 파이프라인 완성)
- [x] `web_recon.py` 신규: HTTP 경로/디렉토리 브루트포싱 (`.git/`, `.env`, `backup*`, `admin` 등 48개 기본 워드리스트, `--wordlist` 파일 지원). 실제 ipTIME 공유기 대상 테스트 중 **오탐 이슈 발견**: catch-all 라우팅(뭘 넣어도 로그인 페이지로 리다이렉트)하는 기기에서는 상태코드만 보고 판정하면 전부 "hit"으로 오탐 → **같은 날 수정**: 존재하지 않는 랜덤 경로로 기준선(baseline)을 먼저 찔러보고, 그 응답(status+length)과 동일한 결과는 `looks_like_catchall=True`로 표시해 실제 발견 목록(`real_hits()`)에서 제외. ipTIME 공유기로 재검증 — 기존엔 48개 전부 오탐이었는데 수정 후 47개 걸러지고 진짜 다른 응답(루트 `/`, 61바이트) 1개만 정상 인식됨
- [x] `vuln_scan.py` 신규: `recon.py` 배너 → NVD keywordSearch로 CVE 매칭. 한계는 5.6절 참고 (재현율 낮은 휴리스틱)
- [x] `recon.py`에 HTTP 배너 그래빙 추가 — HTTP(S) 포트는 raw socket recv 대신 실제 HEAD 요청으로 `Server` 헤더를 읽음 (raw recv로는 아무것도 안 잡힘 — 웹서버는 요청을 받아야 응답하므로)
- [x] `bruteforce.py`에 로깅 강화(`--verbose`로 시도별 로그, 파일 저장) + `--user-wordlist`/`--password-wordlist` 파일 입력 지원
- [x] `pipeline.py`: 인자 없이 실행하면(IDE F5, 더블클릭 등) 대화형으로 IP/계정 입력받도록 수정, 종료 시 Enter 대기 추가
- [x] **KISA CIIP 2026 통합** (`kisa_runner.py`, 5.7절 상세): `vendor/kisa-ciip/`(공개 진단 스크립트 저장소) clone 후 paramiko SFTP로 원격 업로드 + SSH 원격 실행 + 결과 파일 회수/파싱. `report.py`/`pipeline.py`에 연결 완료
- [x] **실제 VM(Ubuntu) 전체 파이프라인 최종 검증**: `python -m breachchain.pipeline 192.168.94.131 --user ubuntu --password ... --limit 3` — 정찰(포트 2개) → CVE 매칭(0건, 5.6절 한계) → KISA CIIP 진단(67개 중 66개 파싱, 양호 46/취약 16/수동 3) → 전술별 ART 실행(3/3 성공) → 통합 리포트(24KB, 모든 섹션 렌더링 확인) 끝까지 완주
- [x] **KISA 통합 중 발견한 버그 2건**: (1) SFTP `mkdir`은 상위 디렉토리를 자동 생성 안 함(`mkdir -p`와 다름) — 원격 base 디렉토리를 SSH `mkdir -p`로 먼저 만들지 않고 바로 SFTP로 파일을 넣으려다 `FileNotFoundError` 발생, 수정. (2) `run_all.sh`가 통합 결과를 stdout이 아니라 **파일로** 저장하고 파일 경로만 한 줄 출력하는 구조인 걸 모르고 stdout 직접 파싱 시도 → 0건 파싱. 원본 스크립트(`lib/result_manager.sh`)를 직접 읽고 나서야 파일 저장 방식인 걸 확인, stdout에서 경로를 정규식으로 뽑아 SFTP로 그 파일만 받아오는 방식으로 수정

### 완료 — Day 8 (실서비스 서버 실전 테스트 + 버그 3건 수정)
- [x] **실전 검증**: 사용자가 실제 운영 중인 서버(트레이딩 봇 등 서비스 구동 중)를 대상으로 `pipeline.py`를 직접 실행. 정찰(포트 3개: 22/80/443) → CVE 매칭(0건) → SSH 인증 시도 3회 만에 **root 계정 취약한 비밀번호로 실제 접속 성공** → KISA 진단 타임아웃으로 실패 → ART 전술 실행(Stealth→Discovery) 진행 중 실서비스 리스크 판단으로 사용자가 직접 중단(Ctrl+C, 정상 종료 확인). **테스트용 계정이었지만, 실제 프로덕션 환경에서 "약한 root 비밀번호"라는 진짜 취약점을 도구가 실제로 찾아낸 최초 사례** — 포트폴리오 서사에서 "그냥 스캐너가 아니라 진짜 뚫었다"는 근거로 쓸 수 있음
- [x] **버그 수정 1**: `pipeline.py`가 `run_kisa_unix()` 호출 시 `timeout=300`을 하드코딩 — 67개 항목이 5분을 넘게 걸리는 서버(트래픽 많은 실서비스 서버 등)에서 타임아웃으로 실패. `--kisa-timeout`(기본 600s) 옵션 추가로 조정 가능하게 수정
- [x] **버그 수정 2**: KISA 진단 실패 시 `logger.info(f"...: {e}")`가 `socket.timeout` 같은 예외에서 빈 문자열을 출력해 원인 파악 불가(`진단 실패, 건너뜀: ` 뒤에 아무것도 안 나옴). `type(e).__name__`을 항상 같이 출력하도록 수정
- [x] **버그 수정 3**: `web_recon.py` catch-all 오탐 문제(Day 7에서 발견만 하고 미수정 상태였음) 해결 — 존재하지 않는 무작위 경로로 기준 응답을 먼저 확보하고, 그 응답(status+length)과 동일한 결과는 `WebHit.looks_like_catchall=True`로 표시해 실제 발견 목록에서 제외. `report.py`도 같이 반영. ipTIME 공유기로 재검증(48개 중 47개가 정확히 걸러지고 진짜 응답 1개만 남음)
- [x] **`--kisa-timeout` 수정 후 재검증**: 사용자 개인 서버 대상으로 `pipeline.py` 전체(정찰→CVE 매칭→KISA CIIP 진단→전술별 ART 실행→통합 리포트) 재실행. KISA 진단이 이번엔 타임아웃 없이 정상 완료됐고, ART 후보 20개 중 14개 성공(전술 순서: Discovery → ... → Collection → Command and Control)까지 끝까지 완주. 유일한 실패는 `T1005`(sqlite 덤프)가 60초 내에 응답 없어 타임아웃 — 개별 명령 타임아웃이지 파이프라인 버그 아님.

---

## 6.5 전술(Tactic) 기반 기법 순환 — 2026-08-13 완료

**질문**: "전술에 맞게 기법들을 돌아가면서 테스트하게 되어있나?" → **이제 그렇다 (Day 6 기준).**

`pipeline.py` 또는 `art_runner.py --by-tactic`을 쓰면 233개(또는 필터링된) 후보를 tactic별로 묶어서(`group_by_tactic()`), ATT&CK 공식 순서(`TACTIC_ORDER`: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Impairment → Stealth → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact)대로 실행한다. 리포트에도 전술 구간이 나뉘어 표시된다.

**단, 아직 "순환"은 아니고 "전술 순서대로 쭉 실행"이다.** 진짜 "상태 기반 순환"(어떤 전술 단계에서 성공하면 다음 전술로 넘어가고, 실패하면 같은 단계에서 다른 후보를 시도하는)이 되려면 **상태 기반 분기 로직**(아래 7-1번)이 필요하다 — 지금은 각 전술 그룹 안의 후보를 성공/실패 관계없이 전부 실행하고 결과만 기록한다.

---

## 7. 남은 작업 (우선순위 순)

1. **상태 기반 분기 로직 (핵심 차별점, 시간 되면)** — tactic별 순차 실행(Day 6)까지는 됐지만, "이 tactic에서 성공하면 다음으로, 실패하면 이 tactic 안에서 다른 후보로"라는 진짜 분기는 없음. ART 후보(`AtomicTest`)에는 `requires`/`provides` 필드가 없으므로, 후보 JSON에 수동/휴리스틱으로 태깅하거나 별도 매핑 테이블이 필요. `state.py`의 assets/credentials/access와 대조해 "지금 실행 가능한 후보"를 계산하는 `eligible_procedures()` 함수가 필요. 마감(일요일) 안에 여유 있으면 시도, 없으면 "다음 확장 포인트"로 정직하게 문서화.

2. **`vuln_scan.py` 재현율 개선** — NVD keywordSearch 대신 CPE 기반 검색(`cpeName`)으로 바꿔야 실제 버전 범위 매칭이 됨 (5.6절 참고). vendor:product CPE 이름 매핑 테이블 필요.

3. **KISA CIIP 다른 카테고리 연결** — 지금 Unix(Debian)만 됨. Windows/웹서버/DBMS/PC는 `vendor/kisa-ciip/`에 이미 있지만 `kisa_runner.py`가 아직 안 건드림.

4. **블라인드 시딩** — 본인이 미리 정답(자격정보 위치 등)을 아는 상태로 테스트하면 "진단 능력"을 증명하지 못한다는 문제의식에서 나온 방향. 별도 시드 스크립트가 무작위로 자격정보/파일 위치를 정하고, 그 결과를 안 본 채로 도구를 실행해 "실제로 탐색해서 찾아냈다"는 서사를 만듦. 미착수, 시간 되면.

5. 자동 테스트 코드 (지금까지 전부 수동 스모크 테스트)

6. **다음 확장 포인트로만 문서화 (이번 범위 밖)**: VM 간 트래픽 가로채기/MITM(ARP 스푸핑 등 별도 도구 필요), 퍼징(별도 카테고리, boofuzz/AFL류 통합 필요)

## 8. 솔직한 현재 수준 평가

"동작하는 프로토타입이자 개념 증명"이고, Day 8 기준으로 **실제 VM뿐 아니라 실서비스 운영 서버에서도 end-to-end 검증**을 마쳤지만 여전히 "실무 도구"는 아님. 이유:
- 상태 관리가 사실상 장식(7-1 미구현) — `state.py`는 실행 이력만 기록할 뿐 assets/credentials/access를 자동으로 채워주는 로직이 없음, 다음 행동을 스스로 결정하지 못함. tactic 순서대로 실행은 하지만 "이 tactic에서 성공했으니 다음 단계로"라는 진짜 판단은 없고 그냥 순서대로 다 실행함
- 에러 처리/재시도 정책 없음
- `#{var}` 치환이 셸 커맨드에 그대로 삽입됨 — 여러 사람이 쓰는 도구라면 인젝션 검토 필요
- 브루트포싱은 SSH 비밀번호 인증만, 기본 계정/비밀번호 목록도 아주 짧음(레인보우테이블/사전 공격 수준 아님) — "약한 기본 계정 찾기" 데모 수준
- 정찰(`recon.py`)은 nmap 없을 때 순수 소켓 스캔으로 폴백하는데, 서비스 버전 탐지 정확도가 nmap보다 크게 떨어짐
- `vuln_scan.py`는 재현율이 낮은 휴리스틱(5.6절) — CVE 0건이 "안전하다"는 뜻이 아님
- KISA CIIP는 Unix(Debian) 카테고리만 연결됨, 625개 중 67개만 실제로 돎
- 브루트포싱으로 계정이 뚫리면 실서비스 서버에서도 그대로 ART 실행 단계로 넘어감 — Day 8 실전 테스트에서 실제로 root 계정이 뚫렸고, 사용자가 리스크 판단해서 수동으로 중단함. 자동으로 "여기부턴 위험하니 확인받고 진행"하는 안전장치가 없음 (지금은 사람이 로그를 보고 직접 판단해야 함)
- cleanup_command가 실제로 VM에 흔적을 남겼다가 지우는 절차라, 일회용/스냅샷 VM이 아니면 위험
- KISA-CIIP 부분은 AGPL-3.0 서드파티 코드를 그대로 실행하는 것 — breachchain이 "만든" 건 그걸 원격 실행 가능하게 감싼 오케스트레이션 레이어(SFTP 업로드/결과 회수/리포트 통합)뿐이라는 걸 명확히 구분해서 설명할 것 (ART와 동일한 원칙, 5.4절 참고)

포트폴리오 서사로는 "확장 가능한 프로토타입, 다만 실제 VM에서 end-to-end로 검증된 결과물"로 포지셔닝하는 게 맞고, 인터뷰에서 "실무 수준으로 가려면 뭐가 더 필요한가"라는 질문에 위 목록으로 답할 준비를 해둘 것.

---

## 9. 커밋 히스토리 참고

- `8ad9804` Day 1: definition loader, executor, and 8 scenario procedures
- `3bd3807` Day 2: state accumulation, ATT&CK mapping, HTML report, demo scenario
- `64aaa6b` Day 3: HTML report, console+file logging, Windows run robustness
- `dc06267` Day 3.5: real ART data pipeline (art_loader.py, fetch_atomics.sh) + full README
- `4801976` README: tactic-based technique rotation not implemented yet
- (다음 커밋: Day 4 — 하드코딩 데모(definitions/, loader.py, scenario.py) 삭제, ART 후보를 cli.py/art_runner.py로 실제 실행 경로에 연결, 접속 사전 체크(check_connection) 추가
  Day 5 — mitreattack-python으로 technique_id → tactic 매핑(tactic_mapping.py) 구현
  Day 6 — paramiko 기반 비밀번호 SSH 인증, recon.py(포트 스캔)/bruteforce.py(SSH 브루트포싱) 신규, art_runner --by-tactic, pipeline.py(통합 진입점) 추가
  Day 7 — web_recon.py/vuln_scan.py 신규, recon.py HTTP 배너 그래빙, KISA CIIP 2026 통합(kisa_runner.py), 실제 VM end-to-end 검증 완료, subprocess 무한대기 버그 수정
  Day 8 — 실서비스 운영 서버 실전 테스트(약한 root 비밀번호 실제 발견), KISA 타임아웃 하드코딩 수정, 빈 예외 메시지 로깅 수정, web_recon.py catch-all 오탐 수정)
