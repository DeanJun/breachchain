"""Maps ATT&CK technique_id -> tactic name(s), using the official STIX dataset
(vendor/mitre-attack/enterprise-attack.json) via mitreattack-python.

ART's own YAML schema (art_loader.py) and our safety-filtered candidate list
(runs/art_safe_candidates.json) carry technique_id but no tactic field, so
this is the missing piece needed before candidates can be grouped/iterated by
tactic (see README section 6.5 / 7-2). One technique can belong to more than
one tactic (e.g. T1078 Valid Accounts spans Initial Access, Persistence,
Privilege Escalation, Defense Evasion), so the mapping is technique_id -> list[str].
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STIX_PATH = REPO_ROOT / "vendor" / "mitre-attack" / "enterprise-attack.json"
DEFAULT_MAPPING_PATH = REPO_ROOT / "runs" / "tactic_mapping.json"


def build_technique_tactic_map(stix_path: Path = DEFAULT_STIX_PATH) -> dict[str, list[str]]:
    """Parse the STIX bundle once and return {technique_id: [tactic names]}
    for every non-revoked/non-deprecated technique and sub-technique.
    """
    from mitreattack.stix20 import MitreAttackData

    if not stix_path.exists():
        raise FileNotFoundError(
            f"{stix_path} not found. Download it first, e.g.:\n"
            "  python -m breachchain.tactic_mapping --fetch"
        )

    mad = MitreAttackData(str(stix_path))
    techniques = mad.get_techniques(remove_revoked_deprecated=True)

    mapping: dict[str, list[str]] = {}
    for t in techniques:
        ext = [r for r in t.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if not ext:
            continue
        technique_id = ext[0]["external_id"]
        tactics = mad.get_tactics_by_technique(t["id"])
        mapping[technique_id] = sorted({tac["name"] for tac in tactics})
    return mapping


def save_mapping(mapping: dict[str, list[str]], path: Path = DEFAULT_MAPPING_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def load_mapping(path: Path = DEFAULT_MAPPING_PATH) -> dict[str, list[str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: python -m breachchain.tactic_mapping"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def tactics_for(technique_id: str, mapping: dict[str, list[str]]) -> list[str]:
    """Look up tactics for a technique_id, falling back to the parent technique
    for sub-techniques (e.g. T1552.001 -> T1552) if the exact id isn't mapped.
    """
    if technique_id in mapping:
        return mapping[technique_id]
    parent_id = technique_id.split(".")[0]
    return mapping.get(parent_id, [])


def group_by_tactic(candidates: list, mapping: dict[str, list[str]]) -> dict[str, list]:
    """Group AtomicTest candidates by tactic name. A candidate whose technique
    spans multiple tactics (e.g. T1078 Valid Accounts) appears under each one.
    Candidates with no resolvable tactic are grouped under "unmapped".
    """
    grouped: dict[str, list] = {}
    for c in candidates:
        tacs = tactics_for(c.technique_id, mapping) or ["unmapped"]
        for t in tacs:
            grouped.setdefault(t, []).append(c)
    return grouped


_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def _fetch_stix(dest: Path = DEFAULT_STIX_PATH) -> None:
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {_STIX_URL} -> {dest} ...")
    urllib.request.urlretrieve(_STIX_URL, dest)
    print("Done.")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if "--fetch" in sys.argv:
        _fetch_stix()
        return 0

    if not DEFAULT_STIX_PATH.exists():
        print(f"{DEFAULT_STIX_PATH} not found. Run with --fetch first, or:")
        print(f"  curl -o {DEFAULT_STIX_PATH} {_STIX_URL}")
        return 1

    mapping = build_technique_tactic_map()
    save_mapping(mapping)
    print(f"기법 {len(mapping)}개에 대한 tactic 매핑 생성 완료: {DEFAULT_MAPPING_PATH}")

    no_tactic = [tid for tid, tacs in mapping.items() if not tacs]
    if no_tactic:
        print(f"주의: tactic이 비어있는 기법 {len(no_tactic)}개: {no_tactic[:10]}{' ...' if len(no_tactic) > 10 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
