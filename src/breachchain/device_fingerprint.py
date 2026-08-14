"""Identify what the target actually is once we have shell access -- OS,
kernel, and (for embedded/IoT boards) hardware model/firmware hints. recon.py
only sees ports/banners from the outside; this runs a handful of read-only
commands over the existing connection so the report can say "this is a
Raspberry Pi running Raspbian 11" instead of just "port 22 open".

Deliberately read-only (uname, cat of /etc and /proc/sys files) -- no writes,
nothing that needs elevation.
"""
from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.executor import Target, _run_on_target
else:
    from .executor import Target, _run_on_target

# /proc/device-tree/model exists on most ARM SBCs (Raspberry Pi, Orange Pi,
# BeagleBone, ...) and is the single most reliable "is this actually a board,
# not a VM/server" signal available without root.
_COMMANDS = {
    "kernel": "uname -a",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "board_model": "cat /proc/device-tree/model 2>/dev/null; echo",
    "cpu_model": "grep -m1 -E 'model name|Hardware|Model' /proc/cpuinfo 2>/dev/null",
    "cpu_arch": "uname -m",
}


@dataclass
class DeviceFingerprint:
    target: str
    kernel: str = ""
    os_release: str = ""
    board_model: str = ""
    cpu_model: str = ""
    cpu_arch: str = ""
    is_likely_embedded: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _os_pretty_name(os_release: str) -> str:
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', os_release, re.MULTILINE)
    return m.group(1) if m else ""


def fingerprint(target: Target, timeout: int = 15) -> DeviceFingerprint:
    values: dict[str, str] = {}
    for key, cmd in _COMMANDS.items():
        _rc, out, _err, timed_out = _run_on_target(cmd, target, timeout)
        values[key] = "" if timed_out else out.strip()

    board_model = values["board_model"].strip("\x00 \n")
    is_embedded = bool(board_model) or values["cpu_arch"] in ("armv6l", "armv7l", "aarch64")

    return DeviceFingerprint(
        target=target.host or target.name,
        kernel=values["kernel"],
        os_release=_os_pretty_name(values["os_release"]) or values["os_release"],
        board_model=board_model,
        cpu_model=values["cpu_model"],
        cpu_arch=values["cpu_arch"],
        is_likely_embedded=is_embedded,
    )
