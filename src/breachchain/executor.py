"""Runs resolved procedure commands, either on the local host or over SSH.

Local execution stands in for the starting node (IoT proxy). SSH execution
represents scope expansion onto a node reached via credentials/access
gathered from a prior procedure.
"""
from __future__ import annotations

import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.art_loader import AtomicTest
else:
    from .art_loader import AtomicTest


@dataclass
class Target:
    """Where a procedure's command actually executes."""

    name: str
    mode: str  # "local" | "ssh"
    host: str | None = None
    user: str | None = None
    key_path: str | None = None
    password: str | None = None  # ssh only; mutually usable with key_path (key tried first if both given)
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


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a process and, on Windows, its whole descendant tree. subprocess's
    own timeout handling only kills the direct child -- if a command spawns
    grandchildren that inherit the stdout/stderr pipes (background jobs,
    `nohup`, some ART test commands), those pipes never see EOF and reading
    them can hang indefinitely even after the direct child is gone.
    """
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True, timeout=10,
        )
    else:
        try:
            proc.kill()
        except OSError:
            pass


def _run_subprocess(argv: list[str], timeout: int, env: dict | None = None) -> tuple[int, str, str, bool]:
    """Run argv with a hard wall-clock bound. Uses background reader threads
    (not subprocess.run's own timeout) so that even if a descendant process
    keeps a stdout/stderr pipe open after the main process is killed, this
    function still returns on time with whatever output was captured so far,
    instead of hanging forever on pipe EOF.
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", env=env,
    )
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def _reader(pipe, sink: list[str]) -> None:
        try:
            for line in iter(pipe.readline, ""):
                sink.append(line)
        except (ValueError, OSError):
            pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_chunks), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_chunks), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    # Daemon threads: if a leaked grandchild is still holding a pipe open,
    # join() with a short cap still lets us return with partial output
    # instead of blocking forever.
    t_out.join(timeout=3)
    t_err.join(timeout=3)

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, "".join(stdout_chunks), "".join(stderr_chunks), timed_out


def _run_ssh(command: str, target: Target, timeout: int) -> tuple[int, str, str, bool]:
    """Run one command over a real SSH connection via paramiko, supporting both
    key-based and password-based auth (unlike shelling out to `ssh`, which needs
    BatchMode=yes to stay non-interactive and therefore can't do password auth
    without sshpass, which isn't reliably available on Windows).
    """
    import paramiko

    if not target.host or not target.user:
        raise ValueError(f"ssh target '{target.name}' requires host and user")
    if not target.key_path and not target.password:
        raise ValueError(f"ssh target '{target.name}' requires key_path or password")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target.host,
            port=target.port,
            username=target.user,
            password=target.password,
            key_filename=target.key_path,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err, False
    except socket.timeout:
        return -1, "", f"{timeout}s 안에 응답 없음 (타임아웃)", True
    except Exception as e:
        return -1, "", str(e), False
    finally:
        client.close()


_SH_CANDIDATES = [
    # Explicit Git for Windows paths first: PATH-based "sh"/"bash" lookups can
    # resolve to C:\Windows\System32\bash.exe, which launches WSL and expects
    # /mnt/c/... paths rather than the C:/... POSIX-style paths used here.
    r"C:\Program Files\Git\usr\bin\sh.exe",
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files\Git\usr\bin\bash.exe",
    "sh",
    "bash",
]


def _resolve_shell() -> str:
    for candidate in _SH_CANDIDATES:
        found = shutil.which(candidate) if not os.path.isabs(candidate) else (
            candidate if os.path.isfile(candidate) else None
        )
        if found:
            return found
    raise FileNotFoundError(
        "No POSIX shell (sh/bash) found on PATH. On Windows, install Git for Windows "
        "and ensure its bin directory is on PATH, or run from a Git Bash terminal."
    )


def _local_shell_env(shell_path: str) -> dict:
    """Build a PATH that includes Git for Windows' coreutils (id, rm, grep, find, ...)
    when we resolved an explicit Git shell path rather than one already on PATH,
    since invoking sh.exe/bash.exe directly does not source Git Bash's own profile.
    """
    env = os.environ.copy()
    git_bin_marker = os.path.join("Git", "usr", "bin")
    idx = shell_path.find(git_bin_marker)
    if idx == -1:
        return env
    git_root = shell_path[: idx + len("Git")]
    extra_dirs = [
        os.path.join(git_root, "usr", "bin"),
        os.path.join(git_root, "bin"),
        os.path.join(git_root, "mingw64", "bin"),
    ]
    existing = env.get("PATH", "")
    env["PATH"] = os.pathsep.join(d for d in extra_dirs if os.path.isdir(d)) + os.pathsep + existing
    return env


def _run_on_target(command: str, target: Target, timeout: int) -> tuple[int, str, str, bool]:
    if target.mode == "local":
        shell = _resolve_shell()
        return _run_subprocess([shell, "-c", command], timeout, _local_shell_env(shell))
    if target.mode == "ssh":
        return _run_ssh(command, target, timeout)
    raise ValueError(f"unknown target mode: {target.mode}")


DEFAULT_TIMEOUT = 60

_PROBE_MARKER = "breachchain-connect-ok"


@dataclass
class ConnectionCheck:
    target_name: str
    ok: bool
    detail: str  # human-readable reason (echoed marker, error output, timeout, etc.)
    duration_s: float


def check_connection(target: Target, timeout: int = 10) -> ConnectionCheck:
    """Verify a target is actually reachable before running anything against it.

    For mode="local" this always succeeds (no network hop involved). For
    mode="ssh" it runs a trivial `echo` over the real ssh connection so
    auth/host-key/network failures surface immediately with a clear reason,
    instead of as a confusing failure on the first real procedure.
    """
    if target.mode == "local":
        return ConnectionCheck(target.name, True, "local target, no connectivity check needed", 0.0)

    t0 = time.monotonic()
    try:
        returncode, stdout, stderr, timed_out = _run_on_target(f"echo {_PROBE_MARKER}", target, timeout)
    except ValueError as e:
        return ConnectionCheck(target.name, False, str(e), 0.0)
    duration = round(time.monotonic() - t0, 3)

    if timed_out:
        return ConnectionCheck(target.name, False, f"{timeout}s 안에 응답 없음 (타임아웃)", duration)
    if returncode != 0:
        return ConnectionCheck(target.name, False, stderr.strip() or f"ssh returncode={returncode}", duration)
    if _PROBE_MARKER not in stdout:
        return ConnectionCheck(target.name, False, f"예상치 못한 응답: {stdout.strip()!r}", duration)
    return ConnectionCheck(target.name, True, f"{target.user}@{target.host}:{target.port} 접속 확인", duration)


def execute(
    test: AtomicTest,
    target: Target,
    argument_overrides: dict[str, str] | None = None,
    run_cleanup: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> ExecutionResult:
    """Resolve and run one real Atomic Red Team test (from art_loader) against one target,
    capturing full output. AtomicTest has no per-test timeout field in ART's schema, so
    timeout is a caller-set ceiling shared across a batch.
    """
    command = test.resolve_command(argument_overrides)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    returncode, stdout, stderr, timed_out = _run_on_target(command, target, timeout)
    duration = time.monotonic() - t0
    ended = datetime.now(timezone.utc)

    if run_cleanup:
        cleanup = test.cleanup_command_resolved(argument_overrides)
        if cleanup:
            _run_on_target(cleanup, target, timeout)

    return ExecutionResult(
        technique_id=test.technique_id,
        display_name=f"{test.technique_display_name} / {test.test_name}",
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


def command_preview(test: AtomicTest, target: Target, argument_overrides: dict[str, str] | None = None) -> str:
    """Return the exact command that would run, without executing it. For local
    targets this is the full shell-quoted argv; for ssh targets (paramiko-based,
    no local argv to build) it's the ssh destination plus the raw command.
    """
    command = test.resolve_command(argument_overrides)
    if target.mode == "local":
        shell = _resolve_shell()
        return " ".join(shlex.quote(a) for a in [shell, "-c", command])
    return f"ssh {target.user}@{target.host}:{target.port} {shlex.quote(command)}"
