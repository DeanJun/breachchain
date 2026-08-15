"""Runs a batch of real, safety-filtered Atomic Red Team candidates
(runs/art_safe_candidates.json, produced by `python -m breachchain.art_loader`)
against one target and produces the same run artifacts as before: JSONL/console
log, state.json, coverage.json, and an HTML report.

This replaces the old scenario.py demo, which chained 5 hand-written
definitions/ procedures in a fixed order purely to exercise the pipeline.

Two orchestration modes:
- run_batch / run_batch_by_tactic: every selected candidate runs regardless
  of prior results (the original behavior).
- run_state_driven: consults state_rules.py's hand-curated requires/provides
  tags before each candidate -- skips ones whose requirements the current
  ScenarioState doesn't meet (logging why), and feeds successful runs'
  provides-effects (e.g. credentials found in stdout) back into state so
  later candidates in the same run can depend on them. See state_rules.py's
  docstring for the honest scope caveat: the safety-filtered pool has very
  few real requires-gated candidates today (no cross-target lateral-movement
  tests survive the filter), so this mostly proves the mechanism and
  populates state for real, rather than demonstrating dramatic branching.
"""
from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.art_loader import AtomicTest, load_candidates
    from breachchain.executor import ExecutionResult, Target, check_connection, execute
    from breachchain.mapping import build_coverage, save_coverage
    from breachchain.report import render_report_html, report_filename, run_timestamp, save_report
    from breachchain.state import ScenarioState
    from breachchain.state_rules import provides_for, requires_for
    from breachchain.tactic_mapping import group_by_tactic, load_mapping
else:
    from .art_loader import AtomicTest, load_candidates
    from .executor import ExecutionResult, Target, check_connection, execute
    from .mapping import build_coverage, save_coverage
    from .report import render_report_html, report_filename, run_timestamp, save_report
    from .state import ScenarioState
    from .state_rules import provides_for, requires_for
    from .tactic_mapping import group_by_tactic, load_mapping

# Standard ATT&CK enterprise-matrix tactic order (attacker's typical progression).
# "Defense Impairment"/"Stealth" reflect this dataset's ATT&CK v18 split of the
# old "Defense Evasion" tactic (see README section 5.5).
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Impairment", "Stealth",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact", "unmapped",
]

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "runs"
REPORTS_DIR = REPO_ROOT / "reports"
LOGS_DIR = REPO_ROOT / "logs"

logger = logging.getLogger("breachchain")


def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)


def _log_step(r: ExecutionResult) -> None:
    status = "PASS" if r.success else "FAIL"
    logger.info(f"[{status}] {r.technique_id} {r.display_name} (target={r.target_name}, {r.duration_s}s)")
    if r.stdout.strip():
        for line in r.stdout.strip().splitlines():
            logger.info(f"    {line}")
    if not r.success and r.stderr.strip():
        for line in r.stderr.strip().splitlines():
            logger.info(f"    ERR {line}")


def select_candidates(
    candidates: list[AtomicTest],
    techniques: list[str] | None,
    limit: int | None,
) -> list[AtomicTest]:
    selected = candidates
    if techniques:
        wanted = set(techniques)
        selected = [c for c in selected if c.technique_id in wanted]
    if limit is not None:
        selected = selected[:limit]
    return selected


def run_batch(
    candidates: list[AtomicTest],
    target: Target,
    run_cleanup: bool = True,
    timeout: int = 60,
) -> tuple[list[ExecutionResult], ScenarioState]:
    state = ScenarioState()
    results: list[ExecutionResult] = []
    for test in candidates:
        r = execute(test, target, run_cleanup=run_cleanup, timeout=timeout)
        _log_step(r)
        results.append(r)
        state.record_step(r.technique_id)
    return results, state


def run_batch_by_tactic(
    candidates: list[AtomicTest],
    target: Target,
    tactic_map: dict[str, list[str]],
    run_cleanup: bool = True,
    timeout: int = 60,
) -> tuple[list[ExecutionResult], ScenarioState, list[str]]:
    """Same as run_batch(), but iterates tactic-by-tactic in ATT&CK order
    (TACTIC_ORDER) instead of the raw candidate order. A candidate whose
    technique spans multiple tactics runs once per tactic it belongs to, so
    the log/report reads as "what was tried at each tactic stage" (README 6.5).

    Still no state-based branching (README 7-1) -- every candidate in a tactic
    group runs regardless of prior results within that group.
    """
    grouped = group_by_tactic(candidates, tactic_map)
    ordered_tactics = [t for t in TACTIC_ORDER if t in grouped]
    ordered_tactics += [t for t in grouped if t not in ordered_tactics]  # any tactic not in our known order

    state = ScenarioState()
    results: list[ExecutionResult] = []
    step_tactics: list[str] = []
    for tactic in ordered_tactics:
        tests = grouped[tactic]
        logger.info(f"=== 전술 단계: {tactic} ({len(tests)}개 후보) ===")
        for test in tests:
            r = execute(test, target, run_cleanup=run_cleanup, timeout=timeout)
            _log_step(r)
            results.append(r)
            step_tactics.append(tactic)
            state.record_step(r.technique_id)
    return results, state, step_tactics


@dataclass
class SkippedCandidate:
    technique_id: str
    test_name: str
    guid: str
    tactic: str
    missing_requirements: list[str]


def run_state_driven(
    candidates: list[AtomicTest],
    target: Target,
    tactic_map: dict[str, list[str]],
    run_cleanup: bool = True,
    timeout: int = 60,
    initial_state: ScenarioState | None = None,
) -> tuple[list[ExecutionResult], ScenarioState, list[str], list[SkippedCandidate], list[str]]:
    """Tactic-ordered execution (same grouping as run_batch_by_tactic), but
    each candidate is gated on state_rules.requires_for() against the
    ScenarioState accumulated so far, and successful runs feed
    state_rules.provides_for() back into that state. See state_rules.py's
    docstring for what's actually gated today (little, honestly) vs. what
    this mechanism is for going forward (multi-target lateral movement).

    initial_state lets a caller seed state before ART execution starts --
    e.g. pipeline.py records a brute-forced credential here so it's not lost
    the moment it's used to open the SSH connection (previously it only lived
    in a local variable and never reached ScenarioState at all).

    Returns (results, state, step_tactics, skipped, dead_end_tactics) --
    skipped candidates never ran (their requirements weren't met), and
    dead_end_tactics lists tactics where every candidate was skipped.
    """
    grouped = group_by_tactic(candidates, tactic_map)
    ordered_tactics = [t for t in TACTIC_ORDER if t in grouped]
    ordered_tactics += [t for t in grouped if t not in ordered_tactics]

    state = initial_state if initial_state is not None else ScenarioState()
    results: list[ExecutionResult] = []
    step_tactics: list[str] = []
    skipped: list[SkippedCandidate] = []
    dead_end_tactics: list[str] = []

    for tactic in ordered_tactics:
        tests = grouped[tactic]
        logger.info(f"=== 전술 단계: {tactic} ({len(tests)}개 후보) ===")
        ran_any = False
        for test in tests:
            requires = requires_for(test.technique_id, test.guid)
            if requires and not state.eligible(requires, target.name):
                missing = [r for r in requires if not state.meets(r, target.name)]
                logger.info(f"[SKIP] {test.technique_id} {test.test_name} -- 미충족 조건: {missing}")
                skipped.append(SkippedCandidate(test.technique_id, test.test_name, test.guid, tactic, missing))
                continue

            r = execute(test, target, run_cleanup=run_cleanup, timeout=timeout)
            _log_step(r)
            results.append(r)
            step_tactics.append(tactic)
            state.record_step(r.technique_id)
            ran_any = True

            if r.success:
                provides = provides_for(test.technique_id, test.guid)
                if provides:
                    before = len(state.credentials)
                    state.apply_provides(provides, r.stdout, target.name, r.technique_id)
                    gained = len(state.credentials) - before
                    if gained:
                        logger.info(f"    -> state 갱신: 자격정보 {gained}개 확보")

        if tests and not ran_any:
            logger.info(f"=== 전술 단계 {tactic}: 후보 {len(tests)}개 전부 조건 미충족으로 건너뜀 (dead end) ===")
            dead_end_tactics.append(tactic)

    return results, state, step_tactics, skipped, dead_end_tactics


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="breachchain-art-runner")
    parser.add_argument("--candidates", type=Path, default=RUNS_DIR / "art_safe_candidates.json")
    parser.add_argument("--technique", action="append", default=None, help="restrict to these technique IDs (repeatable)")
    parser.add_argument("--limit", type=int, default=10, help="max number of candidates to run (default 10; use 0 for all)")
    parser.add_argument("--mode", choices=["local", "ssh"], default="local")
    parser.add_argument("--target-name", default="local-node")
    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--password", help="ssh password (alternative to --key)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--skip-check", action="store_true", help="skip the connectivity pre-check (not recommended)")
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--by-tactic", action="store_true", help="group and run candidates tactic-by-tactic (needs runs/tactic_mapping.json)")
    parser.add_argument("--state-driven", action="store_true", help="tactic-ordered + gate each candidate on state_rules.py requires/provides (implies --by-tactic)")
    args = parser.parse_args()

    limit = None if args.limit == 0 else args.limit
    candidates = load_candidates(args.candidates)
    selected = select_candidates(candidates, args.technique, limit)
    if not selected:
        print("실행할 후보가 없습니다 (--technique 필터를 확인하세요).")
        return 1

    target = Target(
        name=args.target_name,
        mode=args.mode,
        host=args.host,
        user=args.user,
        key_path=args.key,
        password=args.password,
        port=args.port,
    )

    if not args.skip_check:
        check = check_connection(target, timeout=args.connect_timeout)
        status = "OK" if check.ok else "FAIL"
        print(f"[접속 확인: {status}] {target.mode} {target.host or ''}{':' + str(target.port) if target.host else ''} — {check.detail} ({check.duration_s}s)")
        if not check.ok:
            print("대상에 접속할 수 없어 배치 실행을 중단합니다. --host/--user/--key/--port를 확인하거나 --skip-check로 강제 진행하세요.")
            return 1

    ts = run_timestamp()
    _setup_logging(LOGS_DIR / f"log_{ts}.log")

    logger.info(f"breachchain ART batch 시작: {len(selected)}개 후보, target={target.name}({target.mode})")

    step_tactics = None
    skipped = None
    dead_end_tactics = None
    if args.state_driven:
        tactic_map = load_mapping()
        results, state, step_tactics, skipped, dead_end_tactics = run_state_driven(
            selected, target, tactic_map, run_cleanup=not args.no_cleanup, timeout=args.timeout
        )
    elif args.by_tactic:
        tactic_map = load_mapping()
        results, state, step_tactics = run_batch_by_tactic(
            selected, target, tactic_map, run_cleanup=not args.no_cleanup, timeout=args.timeout
        )
    else:
        results, state = run_batch(selected, target, run_cleanup=not args.no_cleanup, timeout=args.timeout)

    state.save(RUNS_DIR / "state.json")

    coverage = build_coverage(results)
    save_coverage(coverage, RUNS_DIR / "coverage.json")

    report_html = render_report_html(
        results, state, coverage, scenario_name="breachchain ART batch run", step_tactics=step_tactics,
        skipped=skipped, dead_end_tactics=dead_end_tactics,
    )
    report_path = REPORTS_DIR / report_filename(ts)
    save_report(report_html, report_path)

    succeeded = sum(1 for r in results if r.success)
    logger.info(f"완료: {succeeded}/{len(results)} 절차 성공")
    logger.info(f"리포트: {report_path}")
    return 0 if succeeded == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
