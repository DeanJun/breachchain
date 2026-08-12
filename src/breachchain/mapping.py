"""Builds an ATT&CK coverage layer from a scenario's execution log.

Full technique/tactic enrichment via mitreattack-python (STIX dataset) is a
later extension point; for the minimum viable scope this aggregates directly
from the execution results, which already carry the technique_id.
"""
from __future__ import annotations

import json
from pathlib import Path

from .executor import ExecutionResult


def build_coverage(results: list[ExecutionResult]) -> dict:
    techniques: dict[str, dict] = {}
    for r in results:
        entry = techniques.setdefault(
            r.technique_id,
            {
                "technique_id": r.technique_id,
                "display_name": r.display_name,
                "attempts": 0,
                "successes": 0,
                "targets": [],
            },
        )
        entry["attempts"] += 1
        entry["successes"] += 1 if r.success else 0
        if r.target_name not in entry["targets"]:
            entry["targets"].append(r.target_name)

    return {
        "name": "breachchain scenario coverage",
        "domain": "enterprise-attack",
        "generated_from": "execution_log",
        "technique_count": len(techniques),
        "techniques": list(techniques.values()),
    }


def save_coverage(coverage: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(coverage, indent=2), encoding="utf-8")
