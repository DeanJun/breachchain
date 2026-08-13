"""breachchain CLI: run one real Atomic Red Team candidate (from
runs/art_safe_candidates.json, produced by `python -m breachchain.art_loader`)
against a target and print/save the result.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.art_loader import find_candidate, load_candidates
    from breachchain.executor import Target, check_connection, execute
else:
    from .art_loader import find_candidate, load_candidates
    from .executor import Target, check_connection, execute

DEFAULT_CANDIDATES_PATH = Path(__file__).resolve().parents[2] / "runs" / "art_safe_candidates.json"
DEFAULT_RUNS_DIR = Path(__file__).resolve().parents[2] / "runs"


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    result = {}
    for pair in pairs:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(f"expected key=value, got '{pair}'")
        key, value = pair.split("=", 1)
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="breachchain-art")
    parser.add_argument("--technique", help="ATT&CK technique ID, e.g. T1552.001 (not required with --check-only)")
    parser.add_argument("--guid", help="disambiguate when a technique has multiple candidate tests")
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES_PATH)
    parser.add_argument("--mode", choices=["local", "ssh"], default="local")
    parser.add_argument("--target-name", default="local-node")
    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--password", help="ssh password (alternative to --key)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--var", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true", help="print resolved command without executing")
    parser.add_argument("--check-only", action="store_true", help="only test connectivity to the target, then exit")
    parser.add_argument("--skip-check", action="store_true", help="skip the connectivity pre-check (not recommended)")
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR / "art_log.jsonl")
    args = parser.parse_args(argv)

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
            print("대상에 접속할 수 없습니다. --host/--user/--key/--port를 확인하거나 --skip-check로 강제 진행하세요.")
            return 1

    if args.check_only:
        return 0

    if not args.technique:
        parser.error("--technique is required unless --check-only is set")

    candidates = load_candidates(args.candidates)
    test = find_candidate(candidates, args.technique, args.guid)
    overrides = _parse_kv(args.var)

    if args.dry_run:
        from .executor import command_preview
        print(f"[{test.technique_id}] {test.technique_display_name} / {test.test_name} (guid={test.guid})")
        print(command_preview(test, target, overrides))
        return 0

    result = execute(test, target, overrides, run_cleanup=not args.no_cleanup, timeout=args.timeout)

    print(f"[{result.technique_id}] {result.display_name} on {result.target_name}")
    print(f"  returncode={result.returncode} success={result.success} duration={result.duration_s}s")
    if result.stdout.strip():
        print("  stdout:")
        for line in result.stdout.splitlines():
            print(f"    {line}")
    if result.stderr.strip():
        print("  stderr:")
        for line in result.stderr.splitlines():
            print(f"    {line}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict()) + "\n")

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
