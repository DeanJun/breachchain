"""Parses the real Atomic Red Team YAML schema (vendor/atomic-red-team/atomics/),
as opposed to the hand-written subset in loader.py/definitions/.

ART's schema nests multiple atomic_tests under one technique file:
    attack_technique: T1552.001
    display_name: '...'
    atomic_tests:
      - name: ...
        supported_platforms: [linux, macos]
        input_arguments: {...}
        executor: {name: sh, command: ..., cleanup_command: ..., elevation_required: true}

This loader parses that shape directly and applies a safety filter before
anything here is ever handed to executor.py.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_VAR_PATTERN = re.compile(r"#\{(\w+)\}")

# Non-Linux-safe / destructive command shapes to exclude even when a test
# claims elevation_required: false and supports linux. This is a heuristic
# safety net, not a guarantee — always dry-run new candidates before executing.
_DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\s+/(?!\S)",       # rm -rf / (root wipe)
    r"\bmkfs\.",
    r"\bdd\s+if=.*of=/dev/",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",  # fork bomb
    r"\b(shutdown|reboot|halt|poweroff)\b",
    r"\biptables\s+-F\b",
    r"\buseradd\b|\buserdel\b|\bpasswd\b",
    r"\bchmod\s+777\s+/(?!\S)",
    r"\bchown\s+-R\s+\S+\s+/(?!\S)",
    r">\s*/dev/sd[a-z]",
    r"\bcrontab\s+-r\b",
    r"\bsystemctl\s+(stop|disable)\s+",
]
_DESTRUCTIVE_RE = re.compile("|".join(_DESTRUCTIVE_PATTERNS), re.IGNORECASE)


@dataclass
class AtomicTest:
    technique_id: str
    technique_display_name: str
    test_name: str
    guid: str
    description: str
    platforms: list[str]
    executor_name: str
    command: str
    cleanup_command: str | None
    elevation_required: bool
    input_arguments: dict[str, dict] = field(default_factory=dict)
    source_path: Path | None = None

    def resolve_command(self, overrides: dict[str, str] | None = None) -> str:
        overrides = overrides or {}
        values = {
            name: overrides.get(name, spec.get("default"))
            for name, spec in self.input_arguments.items()
        }

        def _sub(match: re.Match) -> str:
            var = match.group(1)
            if var not in values or values[var] is None:
                raise ValueError(f"{self.technique_id}/{self.test_name}: missing value for '{var}'")
            return str(values[var])

        return _VAR_PATTERN.sub(_sub, self.command)

    def is_destructive(self) -> bool:
        return bool(_DESTRUCTIVE_RE.search(self.command))

    def cleanup_command_resolved(self, overrides: dict[str, str] | None = None) -> str | None:
        if not self.cleanup_command:
            return None
        overrides = overrides or {}
        values = {
            name: overrides.get(name, spec.get("default"))
            for name, spec in self.input_arguments.items()
        }

        def _sub(match: re.Match) -> str:
            var = match.group(1)
            return str(values.get(var, ""))

        return _VAR_PATTERN.sub(_sub, self.cleanup_command)


# Some ART tests default a search-scope argument to "/" (whole filesystem).
# Recursing a real, live target's "/" walks into /proc and /sys, which contain
# pseudo-files that can block a plain grep/find indefinitely (confirmed against
# an OpenWrt target: `grep -ri password /proc` never returned inside a 20s
# window -- see reports.md 2026-08-15). These are the only two directories
# worth scanning for stashed credentials anyway (home dirs + config files),
# so cap the default there rather than leaving "/" as a live-fire footgun.
# Keyed by (technique_id, guid, argument_name) -> replacement default.
_UNSAFE_WIDE_DEFAULTS = {
    ("T1552.001", "37807632-d3da-442e-8c2e-00f44928ff8f", "file_path"): "$HOME /etc",
    ("T1552.001", "bd4cf0d1-7646-474e-8610-78ccf5a097c4", "file_path"): "$HOME /etc",
    ("T1552.001", "a8f6148d-478a-4f43-bc62-5efee9f931a4", "file_path"): "$HOME /etc",
    ("T1552.001", "aa12eb29-2dbb-414e-8b20-33d34af93543", "file_path"): "$HOME /etc",
    ("T1552.001", "9d9c22c9-fa97-4008-a204-478cf68c40af", "file_path"): "$HOME /etc",
    ("T1552.004", "46959285-906d-40fa-9437-5a439accd878", "search_path"): "$HOME /etc",
    ("T1552.004", "7c247dc7-5128-4643-907b-73a76d9135c3", "search_path"): "$HOME /etc",
    ("T1552.004", "12e4a260-a7fd-4ed8-bf18-1a28c1395775", "search_path"): "$HOME /etc",
    ("T1552.004", "864bb0b2-6bb5-489a-b43b-a77b3a16d68a", "search_path"): "$HOME /etc",
    ("T1552.004", "922b1080-0b95-42b0-9585-b9a5ea0af044", "search_path"): "$HOME /etc",
    ("T1552.004", "2a5a0601-f5fb-4e2e-aa09-73282ae6afca", "search_path"): "$HOME /etc",
    ("T1552.004", "b05ac39b-515f-48e9-88e9-2f141b5bcad0", "search_path"): "$HOME /etc",
}


def _parse_test(technique_id: str, technique_display_name: str, path: Path, raw_test: dict) -> AtomicTest | None:
    executor = raw_test.get("executor") or {}
    command = executor.get("command")
    if not command:
        return None  # manual-only tests with no automatable command
    guid = raw_test.get("auto_generated_guid", "")
    input_arguments = raw_test.get("input_arguments") or {}
    for arg_name, spec in input_arguments.items():
        override = _UNSAFE_WIDE_DEFAULTS.get((technique_id, guid, arg_name))
        if override is not None:
            spec["default"] = override
    return AtomicTest(
        technique_id=technique_id,
        technique_display_name=technique_display_name,
        test_name=raw_test.get("name", "unnamed"),
        guid=guid,
        description=(raw_test.get("description") or "").strip(),
        platforms=raw_test.get("supported_platforms", []),
        executor_name=executor.get("name", ""),
        command=command,
        cleanup_command=executor.get("cleanup_command"),
        elevation_required=bool(executor.get("elevation_required", False)),
        input_arguments=input_arguments,
        source_path=path,
    )


def load_all_tests(atomics_dir: Path) -> list[AtomicTest]:
    """Parse every T*.yaml under atomics_dir into a flat list of AtomicTest."""
    tests: list[AtomicTest] = []
    for path in sorted(atomics_dir.glob("*/T*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            # Some files are unreadable in this environment (e.g. AV quarantine
            # on scripting-technique samples) or malformed; skip rather than abort.
            continue
        if not raw or "atomic_tests" not in raw:
            continue
        technique_id = raw.get("attack_technique", path.stem)
        display_name = raw.get("display_name", technique_id)
        for raw_test in raw["atomic_tests"]:
            test = _parse_test(technique_id, display_name, path, raw_test)
            if test:
                tests.append(test)
    return tests


# Candidates whose default arguments make them impractical to run against a
# real target regardless of the destructive-command/timeout heuristics --
# unlike _UNSAFE_WIDE_DEFAULTS (a fixable scan-scope default), these can't be
# fixed with a saner constant default because the right value depends on the
# target's actual network (we don't know it at candidate-generation time).
# Confirmed against a real OpenWrt target (reports.md 2026-08-15): this sweep
# defaults to subnet 192.168.1.0/24 regardless of the target's real subnet,
# sequentially pinging 254 hosts one at a time -- ran past a 2-minute timeout
# without finishing, on the wrong network the whole time.
_IMPRACTICAL_DEFAULT_GUIDS = {
    "96db2632-8417-4dbb-b8bb-a8b92ba391de",  # T1018 Remote System Discovery - sweep
}


def filter_safe_linux(tests: list[AtomicTest]) -> list[AtomicTest]:
    """Keep only tests that are: linux-capable, sh/bash executed, no elevation
    required, don't match the destructive-command heuristic, and aren't
    known-impractical with their default arguments (_IMPRACTICAL_DEFAULT_GUIDS).
    """
    safe = []
    for t in tests:
        if "linux" not in t.platforms:
            continue
        if t.executor_name not in ("sh", "bash"):
            continue
        if t.elevation_required:
            continue
        if t.is_destructive():
            continue
        if t.guid in _IMPRACTICAL_DEFAULT_GUIDS:
            continue
        safe.append(t)
    return safe


def coverage_summary(tests: list[AtomicTest]) -> dict:
    by_platform: dict[str, int] = {}
    for t in tests:
        for p in t.platforms:
            by_platform[p] = by_platform.get(p, 0) + 1
    by_executor: dict[str, int] = {}
    for t in tests:
        by_executor[t.executor_name] = by_executor.get(t.executor_name, 0) + 1
    return {
        "total_tests": len(tests),
        "unique_techniques": len({t.technique_id for t in tests}),
        "by_platform": by_platform,
        "by_executor": by_executor,
        "elevation_required_count": sum(1 for t in tests if t.elevation_required),
    }


def _default_candidates_path() -> Path:
    return Path(__file__).resolve().parents[2] / "runs" / "art_safe_candidates.json"


def load_candidates(path: Path | None = None) -> list[AtomicTest]:
    """Load the safety-filtered candidate list saved by `main()` (art_safe_candidates.json),
    rehydrated as AtomicTest so callers can use resolve_command()/cleanup_command_resolved().
    """
    path = path or _default_candidates_path()
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: sh scripts/fetch_atomics.sh && python -m breachchain.art_loader"
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        AtomicTest(
            technique_id=d["technique_id"],
            technique_display_name=d["technique_display_name"],
            test_name=d["test_name"],
            guid=d["guid"],
            description="",
            platforms=d["platforms"],
            executor_name=d["executor_name"],
            command=d["command"],
            cleanup_command=d.get("cleanup_command"),
            elevation_required=False,
            input_arguments=d.get("input_arguments") or {},
        )
        for d in raw
    ]


def find_candidate(candidates: list[AtomicTest], technique_id: str, guid: str | None = None) -> AtomicTest:
    matches = [c for c in candidates if c.technique_id == technique_id]
    if guid:
        matches = [c for c in matches if c.guid == guid]
    if not matches:
        raise LookupError(f"no candidate found for technique={technique_id} guid={guid}")
    if len(matches) > 1:
        options = ", ".join(f"{c.guid}({c.test_name})" for c in matches)
        raise LookupError(
            f"multiple candidates for technique={technique_id}, pass --guid to disambiguate: {options}"
        )
    return matches[0]


def _default_atomics_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "vendor" / "atomic-red-team" / "atomics"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    atomics_dir = _default_atomics_dir()
    if not atomics_dir.exists():
        print(f"atomics/ not found at {atomics_dir}")
        print("Run: sh scripts/fetch_atomics.sh")
        return 1

    tests = load_all_tests(atomics_dir)
    safe = filter_safe_linux(tests)

    print(f"전체 파싱된 atomic_tests: {len(tests)}")
    all_summary = coverage_summary(tests)
    for k, v in all_summary.items():
        print(f"  {k}: {v}")

    print()
    print(f"필터 후 (linux + sh/bash + no-elevation + non-destructive): {len(safe)}")
    print(f"고유 기법 수: {len({t.technique_id for t in safe})}")

    out_dir = Path(__file__).resolve().parents[2] / "runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "art_safe_candidates.json"
    out_path.write_text(
        json.dumps(
            [
                {
                    "technique_id": t.technique_id,
                    "technique_display_name": t.technique_display_name,
                    "test_name": t.test_name,
                    "guid": t.guid,
                    "platforms": t.platforms,
                    "executor_name": t.executor_name,
                    "command": t.command,
                    "cleanup_command": t.cleanup_command,
                    "input_arguments": t.input_arguments,
                }
                for t in safe
            ],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"\n필터링된 후보 목록 저장: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
