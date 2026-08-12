"""Runs resolved procedure commands, either on the local host or over SSH.

Local execution stands in for the starting node (IoT proxy). SSH execution
represents scope expansion onto a node reached via credentials/access
gathered from a prior procedure.
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .loader import ProcedureDef


@dataclass
class Target:
    """Where a procedure's command actually executes."""

    name: str
    mode: str  # "local" | "ssh"
    host: str | None = None
    user: str | None = None
    key_path: str | None = None
    port: int = 22


@dataclass
class ExecutionResult:
    technique_id: str
    display_name: str
    target_name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str
    duration_s: float
    success: bool
    timed_out: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _run_subprocess(argv: list[str], timeout: int) -> tuple[int, str, str, bool]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return -1, stdout, stderr, True


def _build_argv(command: str, target: Target) -> list[str]:
    if target.mode == "local":
        return ["sh", "-c", command]
    if target.mode == "ssh":
        if not target.host or not target.user:
            raise ValueError(f"ssh target '{target.name}' requires host and user")
        ssh_cmd = [
            "ssh",
            "-p", str(target.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
        ]
        if target.key_path:
            ssh_cmd += ["-i", target.key_path]
        ssh_cmd.append(f"{target.user}@{target.host}")
        ssh_cmd.append(command)
        return ssh_cmd
    raise ValueError(f"unknown target mode: {target.mode}")


def execute(
    proc_def: ProcedureDef,
    target: Target,
    argument_overrides: dict[str, str] | None = None,
    run_cleanup: bool = True,
) -> ExecutionResult:
    """Resolve and run one procedure against one target, capturing full output."""
    command = proc_def.resolve_command(argument_overrides)
    argv = _build_argv(command, target)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    returncode, stdout, stderr, timed_out = _run_subprocess(argv, proc_def.executor.timeout)
    duration = time.monotonic() - t0
    ended = datetime.now(timezone.utc)

    if run_cleanup:
        cleanup = proc_def.cleanup_command_resolved(argument_overrides)
        if cleanup:
            _run_subprocess(_build_argv(cleanup, target), proc_def.executor.timeout)

    return ExecutionResult(
        technique_id=proc_def.technique_id,
        display_name=proc_def.display_name,
        target_name=target.name,
        command=command,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        started_at=started.isoformat(),
        ended_at=ended.isoformat(),
        duration_s=round(duration, 3),
        success=(returncode == 0 and not timed_out),
        timed_out=timed_out,
    )


def command_preview(proc_def: ProcedureDef, target: Target, argument_overrides: dict[str, str] | None = None) -> str:
    """Return the exact shell-quoted command that would run, without executing it."""
    command = proc_def.resolve_command(argument_overrides)
    argv = _build_argv(command, target)
    return " ".join(shlex.quote(a) for a in argv)
