"""Loads procedure definitions (Atomic Red Team-style YAML, hand-selected subset).

Each definition describes one ATT&CK-mapped procedure: a shell command template
with substitutable input arguments, scoped to the platforms it runs on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_VAR_PATTERN = re.compile(r"#\{(\w+)\}")


@dataclass
class InputArgument:
    name: str
    description: str
    type: str
    default: str | None = None


@dataclass
class ExecutorSpec:
    type: str  # "sh" | "bash"
    command: str
    cleanup_command: str | None = None
    timeout: int = 30


@dataclass
class ProcedureDef:
    technique_id: str
    display_name: str
    description: str
    platforms: list[str]
    executor: ExecutorSpec
    input_arguments: dict[str, InputArgument] = field(default_factory=dict)
    source_path: Path | None = None

    def resolve_command(self, overrides: dict[str, str] | None = None) -> str:
        """Substitute #{var} placeholders with override values or argument defaults."""
        overrides = overrides or {}
        values = {}
        for name, arg in self.input_arguments.items():
            values[name] = overrides.get(name, arg.default)

        def _sub(match: re.Match) -> str:
            var = match.group(1)
            if var not in values or values[var] is None:
                raise ValueError(
                    f"{self.technique_id}: missing value for input argument '{var}'"
                )
            return str(values[var])

        return _VAR_PATTERN.sub(_sub, self.executor.command)

    def cleanup_command_resolved(self, overrides: dict[str, str] | None = None) -> str | None:
        if not self.executor.cleanup_command:
            return None
        overrides = overrides or {}
        values = {
            name: overrides.get(name, arg.default)
            for name, arg in self.input_arguments.items()
        }

        def _sub(match: re.Match) -> str:
            var = match.group(1)
            return str(values.get(var, ""))

        return _VAR_PATTERN.sub(_sub, self.executor.cleanup_command)


def _parse_input_arguments(raw: dict) -> dict[str, InputArgument]:
    parsed = {}
    for name, spec in (raw or {}).items():
        parsed[name] = InputArgument(
            name=name,
            description=spec.get("description", ""),
            type=spec.get("type", "string"),
            default=spec.get("default"),
        )
    return parsed


def load_definition(path: Path) -> ProcedureDef:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    executor_raw = raw["executor"]
    executor = ExecutorSpec(
        type=executor_raw["type"],
        command=executor_raw["command"],
        cleanup_command=executor_raw.get("cleanup_command"),
        timeout=executor_raw.get("timeout", 30),
    )

    return ProcedureDef(
        technique_id=raw["attack_technique"],
        display_name=raw["display_name"],
        description=raw.get("description", "").strip(),
        platforms=raw.get("platforms", ["linux"]),
        executor=executor,
        input_arguments=_parse_input_arguments(raw.get("input_arguments")),
        source_path=path,
    )


def load_all(definitions_dir: Path, platform: str | None = None) -> list[ProcedureDef]:
    """Load every *.yaml definition in a directory, optionally filtered by platform."""
    defs = []
    for path in sorted(definitions_dir.glob("*.yaml")):
        proc = load_definition(path)
        if platform is None or platform in proc.platforms:
            defs.append(proc)
    return defs


def load_by_technique(definitions_dir: Path, technique_id: str) -> ProcedureDef:
    for path in sorted(definitions_dir.glob("*.yaml")):
        proc = load_definition(path)
        if proc.technique_id == technique_id:
            return proc
    raise FileNotFoundError(f"No definition found for technique {technique_id} in {definitions_dir}")
