"""breachchain CLI: run one procedure definition against a target and print/save the result."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .executor import Target, execute
from .loader import load_by_technique

DEFAULT_DEFINITIONS_DIR = Path(__file__).resolve().parents[2] / "definitions"
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
    parser = argparse.ArgumentParser(prog="breachchain")
    parser.add_argument("--technique", required=True, help="ATT&CK technique ID, e.g. T1552.001")
    parser.add_argument("--definitions", type=Path, default=DEFAULT_DEFINITIONS_DIR)
    parser.add_argument("--mode", choices=["local", "ssh"], default="local")
    parser.add_argument("--target-name", default="local-node")
    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--var", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print resolved command without executing")
    parser.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR / "log.jsonl")
    args = parser.parse_args(argv)

    proc_def = load_by_technique(args.definitions, args.technique)
    target = Target(
        name=args.target_name,
        mode=args.mode,
        host=args.host,
        user=args.user,
        key_path=args.key,
        port=args.port,
    )
    overrides = _parse_kv(args.var)

    if args.dry_run:
        from .executor import command_preview
        print(command_preview(proc_def, target, overrides))
        return 0

    result = execute(proc_def, target, overrides, run_cleanup=not args.no_cleanup)

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
