"""End-to-end entry point: give it just an IP (and optionally known
credentials) and it runs recon -> (brute force, if no credentials given) ->
tactic-grouped ART candidate execution -> one HTML report with open ports,
any cracked credentials, and per-tactic technique results.

This is the flow described in README section 7-0: previously the pipeline
assumed SSH access was already granted (art_runner.py alone). This ties
recon.py and bruteforce.py in front of it so a run can genuinely start from
just an IP, matching what a real initial-access phase looks like.

Still no state-based branching (README 7-1): within each tactic, every
selected candidate runs regardless of prior results.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.art_loader import load_candidates
    from breachchain.art_runner import TACTIC_ORDER, run_batch_by_tactic, select_candidates
    from breachchain.bruteforce import DEFAULT_PASSWORDS, DEFAULT_USERS, brute_force_ssh
    from breachchain.executor import Target, check_connection
    from breachchain.mapping import build_coverage, save_coverage
    from breachchain.recon import scan
    from breachchain.report import render_report_html, report_filename, run_timestamp, save_report
    from breachchain.tactic_mapping import load_mapping
    from breachchain.vuln_scan import scan_recon as vuln_scan_recon
    from breachchain.kisa_runner import run_kisa_unix
    from breachchain.device_fingerprint import fingerprint as fingerprint_device
else:
    from .art_loader import load_candidates
    from .art_runner import TACTIC_ORDER, run_batch_by_tactic, select_candidates
    from .bruteforce import DEFAULT_PASSWORDS, DEFAULT_USERS, brute_force_ssh
    from .executor import Target, check_connection
    from .mapping import build_coverage, save_coverage
    from .recon import scan
    from .report import render_report_html, report_filename, run_timestamp, save_report
    from .tactic_mapping import load_mapping
    from .vuln_scan import scan_recon as vuln_scan_recon
    from .kisa_runner import run_kisa_unix
    from .device_fingerprint import fingerprint as fingerprint_device

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "runs"
REPORTS_DIR = REPO_ROOT / "reports"
LOGS_DIR = REPO_ROOT / "logs"

logger = logging.getLogger("breachchain")


def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="breachchain-pipeline")
    parser.add_argument("host", nargs="?", help="target IP/hostname (omit to be prompted -- lets this run via IDE Run/F5 too)")
    parser.add_argument("--user", help="known SSH username (skips brute force if given with --password/--key)")
    parser.add_argument("--password", help="known SSH password")
    parser.add_argument("--key", help="known SSH private key path")
    parser.add_argument("--ssh-port", type=int, default=None, help="SSH port (default: from recon, else 22)")
    parser.add_argument("--candidates", type=Path, default=RUNS_DIR / "art_safe_candidates.json")
    parser.add_argument("--technique", action="append", default=None, help="restrict ART execution to these technique IDs (repeatable)")
    parser.add_argument("--limit", type=int, default=20, help="max ART candidates to run (default 20; use 0 for all 233)")
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--skip-recon", action="store_true")
    parser.add_argument("--skip-bruteforce", action="store_true")
    parser.add_argument("--skip-vuln-scan", action="store_true", help="skip NVD version/CVE lookup (it's a network call per open port, ~6s apart to respect NVD's rate limit)")
    parser.add_argument("--skip-kisa", action="store_true", help="skip the KISA CIIP configuration audit (67 Unix-server items)")
    parser.add_argument("--kisa-platform", default="Debian", help="KISA CIIP Unix platform (default: Debian, matches Ubuntu)")
    parser.add_argument("--kisa-timeout", type=int, default=600, help="KISA CIIP run_all.sh timeout in seconds (default 600 -- 67 items can take 5+ min on a busy/slow target)")
    args = parser.parse_args()

    if not args.host:
        # No CLI args at all -- e.g. launched via IDE Run/F5 rather than a
        # terminal. Prompt instead of letting argparse's "required" error kill it.
        try:
            args.host = input("대상 IP/hostname: ").strip()
        except (EOFError, OSError):
            args.host = ""
        if not args.host:
            print("IP를 입력하지 않아 종료합니다.")
            return 2
        if not args.user:
            user_in = input("알고 있는 SSH 계정 (모르면 그냥 Enter, 브루트포싱 진행): ").strip()
            args.user = user_in or None
        if args.user and not (args.password or args.key):
            pw_in = input(f"{args.user}의 비밀번호 (모르면 그냥 Enter): ").strip()
            args.password = pw_in or None

    ts = run_timestamp()
    _setup_logging(LOGS_DIR / f"log_{ts}.log")

    # 1. Recon: find open ports before assuming anything about access.
    recon_dict = None
    ssh_port = args.ssh_port or 22
    if not args.skip_recon:
        logger.info(f"[정찰] {args.host} 포트 스캔 시작")
        recon_result = scan(args.host)
        recon_dict = recon_result.to_dict()
        logger.info(f"[정찰] 열린 포트 {len(recon_result.open_ports)}개: {[p.port for p in recon_result.open_ports]}")
        open_ssh = [p.port for p in recon_result.open_ports if p.service in ("ssh", "") and p.port in (22, 2222) or p.banner.upper().startswith("SSH")]
        if args.ssh_port is None and open_ssh:
            ssh_port = open_ssh[0]

    # 1.5 Version-based CVE matching, off the banners recon just grabbed.
    vuln_scan_dict = None
    if recon_dict is not None and not args.skip_vuln_scan:
        logger.info("[취약점] 배너 버전 -> NVD CVE 매칭 시작")
        matches = vuln_scan_recon(recon_dict)
        vuln_scan_dict = {"target": args.host, "matches": [m.to_dict() for m in matches]}
        total_cves = sum(len(m.cves) for m in matches)
        logger.info(f"[취약점] CVE {total_cves}건 발견")

    # 2. Credentials: use what's given, else brute-force SSH.
    user, password, key = args.user, args.password, args.key
    bruteforce_dict = None
    if not (user and (password or key)) and not args.skip_bruteforce:
        logger.info(f"[초기 접근] 자격정보 없음 -> {args.host}:{ssh_port} SSH 브루트포싱 시작")
        bf = brute_force_ssh(args.host, ssh_port, DEFAULT_USERS, DEFAULT_PASSWORDS)
        bruteforce_dict = bf.to_dict()
        logger.info(f"[초기 접근] 시도 {bf.attempts}회, 성공 {len(bf.hits)}개")
        if bf.hits:
            user, password = bf.hits[0].user, bf.hits[0].password
            logger.info(f"[초기 접근] 확보한 자격정보 사용: {user}")
        else:
            logger.info("[초기 접근] 자격정보 확보 실패 -> ART 절차 실행은 건너뜀")

    if not (user and (password or key)):
        coverage = build_coverage([])
        save_coverage(coverage, RUNS_DIR / "coverage.json")
        report_html = render_report_html(
            [], _empty_state(), coverage, scenario_name=f"breachchain 진단 리포트: {args.host}",
            recon=recon_dict, bruteforce=bruteforce_dict, vuln_scan=vuln_scan_dict,
        )
        report_path = REPORTS_DIR / report_filename(ts)
        save_report(report_html, report_path)
        logger.info(f"자격정보를 확보하지 못해 절차 실행 없이 종료. 리포트: {report_path}")
        return 1

    target = Target(name=args.host, mode="ssh", host=args.host, user=user, password=password, key_path=key, port=ssh_port)
    check = check_connection(target)
    logger.info(f"[접속 확인: {'OK' if check.ok else 'FAIL'}] {check.detail}")
    if not check.ok:
        return 1

    # 2.5 Device fingerprint: what is this actually -- a Raspberry Pi running
    # Raspbian, or a generic Ubuntu VM? IoT/embedded targets show a board
    # model (/proc/device-tree/model) and an ARM arch; servers don't.
    fp = fingerprint_device(target)
    logger.info(f"[식별] {fp.os_release or '(OS 확인 불가)'} / {fp.cpu_arch}"
                + (f" / 보드: {fp.board_model}" if fp.board_model else "")
                + (" -- IoT/임베디드 장비로 추정" if fp.is_likely_embedded else ""))
    fingerprint_dict = fp.to_dict()

    # 3. KISA CIIP configuration audit -- a different question than ART
    # ("is this technique reproducible") or vuln_scan ("does this banner
    # version have known CVEs"): "does this config comply with KISA's
    # technical vulnerability assessment guide". Runs once access exists,
    # same as ART, but checks 67 config items instead of trying exploits.
    kisa_dict = None
    if not args.skip_kisa:
        try:
            logger.info(f"[KISA] {args.kisa_platform} 기술적 취약점 진단 시작 (67개 항목)")
            kisa_results = run_kisa_unix(target, platform=args.kisa_platform, timeout=args.kisa_timeout)
            good = sum(1 for r in kisa_results if r.final_result == "GOOD")
            vuln = sum(1 for r in kisa_results if r.final_result == "VULNERABLE")
            logger.info(f"[KISA] 완료: 양호 {good} / 취약 {vuln} / 총 {len(kisa_results)}")
            kisa_dict = {"target": args.host, "platform": args.kisa_platform, "results": [r.to_dict() for r in kisa_results]}
        except Exception as e:
            # str(e) is empty for some exceptions (e.g. socket.timeout), which
            # used to print a useless "진단 실패, 건너뜀: " with no reason --
            # always show the exception type so there's something to go on.
            detail = str(e) or "(추가 정보 없음)"
            logger.info(f"[KISA] 진단 실패, 건너뜀: {type(e).__name__}: {detail}")

    # 4. Tactic-grouped ART execution.
    candidates = load_candidates(args.candidates)
    limit = None if args.limit == 0 else args.limit
    selected = select_candidates(candidates, args.technique, limit)
    tactic_map = load_mapping()

    logger.info(f"[진단] {len(selected)}개 후보를 전술 순서대로 실행")
    results, state, step_tactics = run_batch_by_tactic(
        selected, target, tactic_map, run_cleanup=not args.no_cleanup, timeout=args.timeout
    )
    state.save(RUNS_DIR / "state.json")

    coverage = build_coverage(results)
    save_coverage(coverage, RUNS_DIR / "coverage.json")

    report_html = render_report_html(
        results, state, coverage, scenario_name=f"breachchain 진단 리포트: {args.host}",
        step_tactics=step_tactics, recon=recon_dict, bruteforce=bruteforce_dict, vuln_scan=vuln_scan_dict, kisa=kisa_dict,
        fingerprint=fingerprint_dict,
    )
    report_path = REPORTS_DIR / report_filename(ts)
    save_report(report_html, report_path)

    succeeded = sum(1 for r in results if r.success)
    logger.info(f"완료: {succeeded}/{len(results)} 절차 성공")
    logger.info(f"리포트: {report_path}")
    return 0


def _empty_state():
    if __package__ in (None, ""):
        from breachchain.state import ScenarioState
    else:
        from .state import ScenarioState
    return ScenarioState()


if __name__ == "__main__":
    exit_code = main()
    if len(sys.argv) <= 1:
        # No CLI args given (IDE Run/F5, double-click) -- keep the console open
        # so the output/report path doesn't vanish the instant it's printed.
        try:
            input("\n작업이 끝났습니다. 창을 닫으려면 Enter를 누르세요...")
        except (EOFError, OSError):
            pass
    raise SystemExit(exit_code)
