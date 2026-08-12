"""Runs the built-in demo scenario chain end-to-end and produces run artifacts.

Chain: credential harvest on the starting node -> validate access on the
internal node -> discover the goal asset -> read it -> cleanup traces.
This exercises loader -> executor -> state -> mapping -> report against a
real (if minimal) run, without requiring provisioned VMs.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from .executor import Target, execute
from .loader import load_by_technique
from .mapping import build_coverage, save_coverage
from .report import render_report_html, report_filename, save_report
from .state import ScenarioState

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFINITIONS_DIR = REPO_ROOT / "definitions"
RUNS_DIR = REPO_ROOT / "runs"
REPORTS_DIR = REPO_ROOT / "reports"

CRED_PATTERN = re.compile(r"(\w+)[:=]\s*([^\s]+)$", re.MULTILINE)


def run_demo(
    iot_dir: Path,
    internal_dir: Path,
    run_id: str = "demo",
) -> tuple[list, ScenarioState]:
    state = ScenarioState()
    results = []

    iot_target = Target(name="iot-node", mode="local")
    internal_target = Target(name="internal-node", mode="local")

    state.add_asset("iot-node", "node", discovered_via="scenario-start")

    # Step 1: harvest credentials from the starting node's config
    proc = load_by_technique(DEFINITIONS_DIR, "T1552.001")
    r1 = execute(proc, iot_target, {"search_path": iot_dir.as_posix()})
    results.append(r1)
    state.record_step(r1.technique_id)
    if r1.success and r1.stdout.strip():
        for line in r1.stdout.splitlines():
            m = CRED_PATTERN.search(line)
            if m and "password" in line.lower():
                state.add_credential(
                    identity=m.group(2), source_asset="iot-node", discovered_via=r1.technique_id
                )

    # Step 2: validate the harvested credentials grant access on the internal node
    proc = load_by_technique(DEFINITIONS_DIR, "T1078")
    r2 = execute(proc, internal_target, {"remote_user": "svc-app"})
    results.append(r2)
    state.record_step(r2.technique_id)
    if r2.success:
        state.add_asset("internal-node", "node", discovered_via=r2.technique_id)
        state.add_access("internal-node", "user", discovered_via=r2.technique_id)

    # Step 3: discover the goal asset on the internal node
    proc = load_by_technique(DEFINITIONS_DIR, "T1083")
    r3 = execute(proc, internal_target, {"search_path": internal_dir.as_posix()})
    results.append(r3)
    state.record_step(r3.technique_id)
    goal_file = internal_dir / "objective.txt"
    if r3.success and goal_file.exists():
        state.add_asset(str(goal_file), "file", discovered_via=r3.technique_id)

    # Step 4: read the goal asset (scenario objective reached)
    proc = load_by_technique(DEFINITIONS_DIR, "T1005")
    r4 = execute(proc, internal_target, {"target_file": goal_file.as_posix()})
    results.append(r4)
    state.record_step(r4.technique_id)
    if r4.success and r4.stdout.strip():
        state.add_access(str(goal_file), "read", discovered_via=r4.technique_id)

    # Step 5: cleanup traces
    artifact = Path(tempfile.gettempdir()) / "breachchain-run-artifact"
    artifact.write_text("scenario run marker\n", encoding="utf-8")
    proc = load_by_technique(DEFINITIONS_DIR, "T1070.004")
    r5 = execute(proc, internal_target, {"artifact_path": artifact.as_posix()})
    results.append(r5)
    state.record_step(r5.technique_id)

    return results, state


def _ensure_fixtures(base: Path) -> tuple[Path, Path]:
    iot_dir = base / "iot"
    internal_dir = base / "internal"
    iot_dir.mkdir(parents=True, exist_ok=True)
    internal_dir.mkdir(parents=True, exist_ok=True)
    (iot_dir / "config.yml").write_text(
        "service: iot-gateway\nadmin_user: svc-app\nadmin_password: S3rvice!2024\n",
        encoding="utf-8",
    )
    (internal_dir / "objective.txt").write_text(
        "CLASSIFIED: internal billing export access confirmed.\n", encoding="utf-8"
    )
    return iot_dir, internal_dir


def main() -> int:
    base = Path(tempfile.gettempdir()) / "breachchain-demo"
    iot_dir, internal_dir = _ensure_fixtures(base)

    results, state = run_demo(iot_dir, internal_dir)

    state.save(RUNS_DIR / "state.json")

    coverage = build_coverage(results)
    save_coverage(coverage, RUNS_DIR / "coverage.json")

    report_html = render_report_html(results, state, coverage, scenario_name="breachchain demo scenario")
    report_path = REPORTS_DIR / report_filename()
    save_report(report_html, report_path)

    succeeded = sum(1 for r in results if r.success)
    print(f"Demo scenario: {succeeded}/{len(results)} steps succeeded")
    print(f"Report written to {report_path}")
    return 0 if succeeded == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
