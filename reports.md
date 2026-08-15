# 발견 사항 노트 (findings)

`reports/`(gitignore 대상, HTML 실행 리포트)와 별도로, 테스트 중 발견한 의미 있는 관찰/인사이트를 여기 기록한다. 실행 결과 자체가 아니라 "왜 그런 결과가 나왔는가"에 대한 해석을 남기는 문서.

---

## 2026-08-15: OpenWrt(BusyBox) 대상 ART 실행 — 환경 불일치가 진단 정보가 되는 사례

### 상황
IoT 모뎀/공유기를 흉내내기 위해 OpenWrt 25.12.5(x86_64) VM을 만들고, `pipeline.py`로 실제 ART 후보 20개(전술 순서: Stealth → Discovery)를 실행했다.

### 관찰
ART 절차 상당수가 `ash: xxx: not found` 형태로 실패했다:
- `truncate: not found`, `arp: not found`, `systemctl: not found`, `gcc`/`clang`/`g++`/`go: not found`

### 원인
OpenWrt는 **BusyBox 기반**이라 셸이 `bash`가 아니라 `ash`이고, `truncate`/`arp`/`systemctl`/`gcc` 같은 GNU coreutils/일반 리눅스 도구가 기본적으로 없다. ART의 절차 정의는 `supported_platforms: [linux]`라고만 표시하지만, 실제로는 **"GNU/Linux(데스크톱·서버, coreutils+bash 존재)"를 암묵적으로 전제**하고 있다. `art_loader.py`의 안전 필터(`filter_safe_linux`)는 이 차이를 구분하지 못한다 — "linux 태그가 있으니 실행 가능하다"와 "실제로 이 환경에서 실행된다"는 다른 문제다.

### 왜 이게 버그가 아니라 발견인가
1. **정확히 이게 진단하려던 것과 같은 종류의 정보다.** "이 절차가 이 환경에서 재현 가능한가"라는 질문에 대해, 실패 자체가 "이 환경은 표준 GNU/Linux 도구 체인이 없는 경량 임베디드 환경"이라는 답을 준다. 성공/실패 로그만 봐도 대상이 일반 서버가 아니라는 게 드러난다.
2. **성공한 절차들은 실제로 유효한 정보를 수집했다** — `T1027`(base64 디코딩), `T1016`(네트워크 설정 확인, `ifconfig`/`ip addr` 둘 다 동작), `T1007`(init.d 서비스 목록으로 `dropbear`/`uhttpd`/`dnsmasq` 등 실행 중인 서비스 확인) 등은 BusyBox 환경에서도 정상 동작해서 실제 정찰 정보를 남겼다.
3. **포트폴리오 서사로 쓸 수 있다**: "표준 ART 절차 라이브러리를 IoT 대상에 그대로 돌려보면, 대상 환경과 절차가 전제하는 환경 사이의 실행 가능성 차이 자체가 하나의 진단 결과가 된다"는 관찰은, JD가 요구하는 "IoT 단말 보안 진단" 역량과 정확히 맞닿아 있다.

### 다음에 다룰 수 있는 개선 방향 (아직 미착수)
- `art_loader.py` 필터에 "embedded/busybox" 서브카테고리를 추가해, coreutils 의존성이 적은 절차만 별도로 골라내는 필터(`filter_safe_embedded()` 같은)를 만들 수 있음
- 리포트(`report.py`)에 "환경 불일치로 인한 실패"와 "진짜 방어/차단으로 인한 실패"를 구분하는 표시를 추가하면 더 정확한 진단 리포트가 됨 (지금은 둘 다 그냥 FAIL로만 표시됨)

### 같은 세션에서 추가로 발견한 것: 서브넷 스윕 절차의 하드코딩된 기본값
`T1018 Remote System Discovery - sweep`(`for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip; ...`)이 대상의 실제 서브넷(`192.168.204.0/24`)과 무관하게 기본값 `192.168.1.0/24`로 254개 순차 ping을 돈다. `art_runner.py`/`pipeline.py`는 `cli.py`와 달리 `--var` 오버라이드가 없어서 배치 실행 중엔 고칠 방법이 없었다. 실제로 "멈춘 것처럼 보이는" 현상의 원인이었음 — 무한 정지가 아니라 잘못된 서브넷을 오래 순회하는 것.

---

## 2026-08-15: 상태 기반 분기(state_rules.py) 최초 구현

### 계기
위 OpenWrt 테스트 중 "OS/환경에 따라 스캔 방식을 바꿔야 하는 것 아니냐"는 질문에서 시작해, 원래 기획서의 핵심 차별점이었던 "상태 기반 분기 로직"(README 7-1)을 실제로 구현했다.

### 구현
- `state_rules.py` 신규: 후보(`technique_id`, `guid`) 단위로 `requires`(실행 전제조건)/`provides`(성공 시 효과) 수동 태깅. ART 원본 YAML엔 이 필드가 없어서 별도 관리 테이블로 뺐다.
- `state.py`에 `eligible()`/`meets()`/`apply_provides()` 추가 — `"credential"`, `"access:<level>"` 두 가지 predicate 지원.
- `art_runner.py`에 `run_state_driven()` 신규 — tactic 순서로 돌되, 각 후보 실행 전 `requires` 충족 여부를 확인해 미충족이면 SKIP(사유 로깅), 충족이면 실행 후 성공 시 `provides` 효과를 state에 반영. 한 tactic의 후보가 전부 SKIP되면 "dead end"로 기록.
- `pipeline.py`가 `run_batch_by_tactic` 대신 `run_state_driven`을 쓰도록 전환. 브루트포싱으로 찾은 자격정보도 `initial_state`로 시드해서 이제 진짜 `state.json`에 남는다 (전엔 지역변수로만 존재).
- `report.py`에 "건너뛴 후보(상태 조건 미충족)" 섹션과 "막힌 전술 단계(dead end)" 표시 추가.

### 검증
- fixture 파일(`db_password: S3cret!23`)로 `T1552.001`(grep) 실행 → `provides: credential` 적용 → `state.credentials`에 정확히 `S3cret!23` 반영 확인
- `state.eligible()`이 `credential`/`access:root` predicate 각각 조건 미충족→충족 전환을 정확히 판별 확인
- `render_report_html()`에 skipped/dead_end_tactics 넘겼을 때 리포트에 해당 섹션 정상 렌더링 확인
- 실제 OpenWrt 대상으로 `--technique` 필터 조합 스모크 테스트 정상 완료

### 정직한 한계 (README 6.5/7-1에도 기록)
안전 필터를 통과한 233개 후보는 전부 "이미 접속된 단일 대상 안에서" 도는 절차라, 실제로 `requires`가 유의미하게 게이팅하는 경우가 거의 없다 (T1078/T1021 같은 "찾은 자격정보로 다른 호스트 접속" 류는 안전 필터에서 이미 빠짐 — 권한 상승/2차 대상 필요). 그래서 이번 구현은 **메커니즘 자체(게이팅 + state 실제 population)는 검증됐지만, 극적인 분기를 보여주는 사례는 아직 부족**하다. 진짜 분기가 의미를 가지려면 다중 호스트 오케스트레이션(찾은 자격정보로 새 대상에 자동 연결)이 필요하고, 이건 다음 우선순위로 남겨뒀다.

---

## 2026-08-15: 실제 OpenWrt 대상으로 state-driven 파이프라인 검증 중 발견 — `grep -ri password /`가 `/proc`에서 멈춤

### 상황
`--state-driven`을 실제 OpenWrt VM(`root:1234`)에 돌리다가 `T1552.001 Extract passwords with grep`에서 90초 타임아웃 이후로도 멈춘 것처럼 보임.

### 원인 확인
`T1552.001`(및 `T1552.004` 등) 여러 ART 후보의 `file_path`/`search_path` 기본값이 **`/`(파일시스템 루트)**였다. `/etc`만 줬을 때는 0.07초, `/proc`을 줬을 때는 20초 타임아웃까지 끝내 응답 없음으로 재현 확인 — `/proc`의 가상 파일(크기가 무한대로 잡히거나 블로킹되는 pseudo-file)을 grep이 읽다가 멈추는 게 원인. OpenWrt/BusyBox뿐 아니라 일반 GNU/Linux에서도 `grep -r /`은 실무에서 흔히 걸리는 함정이다.

### 조치
`art_loader.py`에 `_UNSAFE_WIDE_DEFAULTS` 테이블 추가 — `file_path`/`search_path` 기본값이 `/`인 12개 후보(`T1552.001` 5개, `T1552.004` 7개)를 `$HOME /etc`로 강제 축소. `find`/`grep` 둘 다 공백으로 구분된 여러 경로를 그대로 받아들이는 걸 이용해, 명령 템플릿(`#{file_path}/.aws` 등)을 건드리지 않고 안전하게 범위를 줄였다. `python -m breachchain.art_loader`로 후보 JSON 재생성 후, 실제 OpenWrt 대상으로 같은 후보가 0.1초에 정상 완료되는 것까지 재검증.

### 남은 한계
`/proc`/`/sys`를 원천적으로 배제하는 게 아니라 "스캔 범위를 좁혀서 우회"한 수준이다. `art_loader.py`의 파서가 커맨드 템플릿(`grep -r #{file_path}` 등)을 이해하고 위험한 재귀 대상을 일반적으로 탐지하는 건 아니라서, 앞으로 안전 필터를 재생성(ART 저장소 업데이트 등)할 때마다 이 표를 수동으로 유지해야 한다.
