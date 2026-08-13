"""Runs KISA CIIP 2026 technical vulnerability assessment scripts
(vendor/kisa-ciip/, cloned from https://github.com/rebugui/KISA-CIIP-2026)
against a remote SSH target, and parses their JSON verdicts.

Where this fits vs. the ART pipeline: ART candidates (art_loader.py/art_runner.py)
answer "can this attacker technique be reproduced here". KISA CIIP items answer
"is this specific configuration compliant with the KISA 기술적 취약점 진단 가이드"
(e.g. U-01 root 계정 원격 접속 제한). Different question, same target -- this is
meant to run *alongside* the ART pipeline, feeding a report section of its own,
not replacing it.

How it actually runs: KISA-CIIP's run_all.sh scripts are meant to be executed
*on* the target (they source ../../lib/*.sh relative to their own path and use
target-local commands like systemctl/grep/awk). So this module:
  1. SFTPs lib/ + the chosen category/platform script directory to a temp
     path on the target.
  2. Runs run_all.sh over SSH with UNIX_RUNALL_MODE=1, which makes every
     check print its JSON verdict straight to stdout (see result_manager.sh
     save_dual_result -> is_runall_mode branch) instead of writing files --
     so there's nothing to fetch back afterward.
  3. Extracts each JSON object from the combined stdout (brace-depth
     matching, same approach run_all.sh itself uses in bash) and parses it.

Only the "01.Unix서버" category is wired up (matches the Ubuntu/Debian test
target this project has actually been run against). Windows/DBMS/web
categories exist in the vendor repo but aren't executed by this module yet.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.executor import Target
else:
    from .executor import Target

logger = logging.getLogger("breachchain")

REPO_ROOT = Path(__file__).resolve().parents[2]
KISA_VENDOR_DIR = REPO_ROOT / "vendor" / "kisa-ciip"
KISA_LIB_DIR = KISA_VENDOR_DIR / "lib"

# category dir name -> {platform: (script_dir_name, run_all_filename)}
UNIX_PLATFORMS = {
    "Debian": ("01.Unix서버/Debian", "01.Unix서버_Debian_run_all.sh"),
    "RedHat": ("01.Unix서버/RedHat", "01.Unix서버_RedHat_run_all.sh"),
    "AIX": ("01.Unix서버/AIX", "01.Unix서버_AIX_run_all.sh"),
    "HP-UX": ("01.Unix서버/HP-UX", "01.Unix서버_HP-UX_run_all.sh"),
    "Solaris": ("01.Unix서버/Solaris", "01.Unix서버_Solaris_run_all.sh"),
}

REMOTE_BASE_DIR = "/tmp/breachchain-kisa-ciip"


@dataclass
class KisaCheckResult:
    item_id: str
    item_name: str
    status: str  # 양호 | 취약 | 수동진단 | N/A
    final_result: str  # GOOD | VULNERABLE | MANUAL | N/A
    summary: str
    command: str
    command_result: str
    guideline: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _iter_json_objects(text: str) -> list[str]:
    """Extract top-level {...} JSON blobs from mixed stdout, tracking brace
    depth so nested braces inside a result (e.g. command_result containing
    literal `{`) don't split one object into two. Mirrors run_all.sh's own
    awk-based extraction of embedded JSON from a script's stdout.
    """
    objects = []
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    objects.append(text[start : i + 1])
                    start = None
    return objects


def _to_check_result(raw: dict) -> KisaCheckResult:
    inspection = raw.get("inspection", {})
    return KisaCheckResult(
        item_id=raw.get("item_id", ""),
        item_name=raw.get("item_name", ""),
        status=inspection.get("status", ""),
        final_result=raw.get("final_result", ""),
        summary=inspection.get("summary", ""),
        command=raw.get("command", ""),
        command_result=raw.get("command_result", ""),
        guideline=raw.get("guideline", {}),
    )


def parse_results(stdout: str) -> list[KisaCheckResult]:
    """Parse individual per-item JSON blobs directly embedded in stdout
    (single-check.sh mode, not run_all.sh's aggregated-file mode below).
    """
    results = []
    for blob in _iter_json_objects(stdout):
        try:
            raw = json.loads(blob)
        except json.JSONDecodeError:
            continue
        if "item_id" not in raw:
            continue
        results.append(_to_check_result(raw))
    return results


def parse_aggregated_json(text: str) -> list[KisaCheckResult]:
    """Parse run_all.sh's aggregated results file (the {"category", ...,
    "items": [...]} shape written by result_manager.sh's
    create_runall_aggregated_results -- see that function for the exact schema).
    """
    data = json.loads(text)
    return [_to_check_result(item) for item in data.get("items", [])]


_AGGREGATED_PATH_RE = re.compile(r"통합 JSON 결과 저장:\s*(\S.*\.json)")


def _sftp_put_dir(sftp, local_dir: Path, remote_dir: str) -> None:
    try:
        sftp.mkdir(remote_dir)
    except OSError:
        pass  # already exists
    for entry in local_dir.iterdir():
        remote_path = remote_dir + "/" + entry.name
        if entry.is_dir():
            _sftp_put_dir(sftp, entry, remote_path)
        else:
            sftp.put(str(entry), remote_path)


def _connect(target: Target, timeout: int):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=target.host, port=target.port, username=target.user,
        password=target.password, key_filename=target.key_path,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        look_for_keys=False, allow_agent=False,
    )
    return client


def run_kisa_unix(target: Target, platform: str = "Debian", timeout: int = 300) -> list[KisaCheckResult]:
    """Upload the KISA CIIP Unix-server scripts for `platform` to the target
    over SFTP, run its run_all.sh over SSH, and parse the JSON verdicts it
    prints. Requires vendor/kisa-ciip/ to exist locally (git clone it first).
    """
    if platform not in UNIX_PLATFORMS:
        raise ValueError(f"unsupported platform '{platform}', choose from {list(UNIX_PLATFORMS)}")
    if not KISA_VENDOR_DIR.exists():
        raise FileNotFoundError(
            f"{KISA_VENDOR_DIR} not found. Run: git clone https://github.com/rebugui/KISA-CIIP-2026.git {KISA_VENDOR_DIR}"
        )

    script_dir_name, run_all_filename = UNIX_PLATFORMS[platform]
    local_script_dir = KISA_VENDOR_DIR / script_dir_name

    client = _connect(target, timeout=min(timeout, 30))
    try:
        # SFTP's mkdir doesn't create parents (unlike `mkdir -p`), so every
        # intermediate dir has to exist before any nested put; wipe any stale
        # prior run first.
        remote_platform_root = f"{REMOTE_BASE_DIR}/01.Unix서버/{platform}"
        _stdin, _stdout, _stderr = client.exec_command(
            f"rm -rf '{REMOTE_BASE_DIR}' && mkdir -p '{REMOTE_BASE_DIR}/lib' '{remote_platform_root}'"
        )
        _stdout.channel.recv_exit_status()

        sftp = client.open_sftp()
        logger.info(f"[KISA] lib/ + {platform} 스크립트 업로드 중 -> {REMOTE_BASE_DIR}")
        _sftp_put_dir(sftp, KISA_LIB_DIR, f"{REMOTE_BASE_DIR}/lib")
        # KISA scripts resolve lib via "../../lib" relative to the script's own
        # path, so the remote layout has to mirror the two-levels-deep nesting.
        _sftp_put_dir(sftp, local_script_dir, remote_platform_root)
        sftp.close()

        remote_run_all = f"{remote_platform_root}/{run_all_filename}"
        logger.info(f"[KISA] {platform} 전체 항목 진단 실행 중 (원격, 최대 {timeout}s)...")
        stdin, stdout, stderr = client.exec_command(f"chmod +x '{remote_run_all}' && bash '{remote_run_all}'", timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()

        if rc not in (0,) and not out.strip():
            logger.info(f"[KISA] 원격 실행 실패 (returncode={rc}): {err.strip()[:500]}")
            return []

        # run_all.sh writes the combined verdict as a *file* on the target
        # (result_manager.sh's create_runall_aggregated_results), not to
        # stdout -- it only echoes that file's path, which we grab back over
        # the same SFTP connection.
        match = _AGGREGATED_PATH_RE.search(out)
        if not match:
            logger.info("[KISA] 통합 결과 파일 경로를 stdout에서 찾지 못함 (스크립트 출력 형식이 바뀌었을 수 있음)")
            logger.info(f"[KISA] stdout 마지막 500자: {out.strip()[-500:]}")
            return []
        remote_json_path = match.group(1).strip()

        sftp = client.open_sftp()
        try:
            with sftp.open(remote_json_path, "r") as f:
                aggregated_text = f.read().decode("utf-8")
        finally:
            sftp.close()
    finally:
        client.close()

    results = parse_aggregated_json(aggregated_text)
    logger.info(f"[KISA] {len(results)}개 항목 파싱 완료 (통합 결과: {remote_json_path})")
    return results


def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="breachchain-kisa-runner")
    parser.add_argument("host")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password")
    parser.add_argument("--key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--platform", default="Debian", choices=list(UNIX_PLATFORMS))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "runs" / "kisa_results.json")
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()

    log_path = args.log or REPO_ROOT / "logs" / f"kisa_{datetime.now().strftime('%y%m%d_%H%M%S')}.log"
    _setup_logging(log_path)

    target = Target(name=args.host, mode="ssh", host=args.host, user=args.user, password=args.password, key_path=args.key, port=args.port)
    results = run_kisa_unix(target, platform=args.platform, timeout=args.timeout)

    good = sum(1 for r in results if r.final_result == "GOOD")
    vuln = sum(1 for r in results if r.final_result == "VULNERABLE")
    manual = sum(1 for r in results if r.final_result == "MANUAL")
    logger.info(f"완료: 양호 {good} / 취약 {vuln} / 수동진단 {manual} / 총 {len(results)}")
    for r in results:
        if r.final_result == "VULNERABLE":
            logger.info(f"  [취약] {r.item_id} {r.item_name}: {r.summary}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"target": args.host, "platform": args.platform, "results": [r.to_dict() for r in results]}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info(f"저장: {args.out}")
    logger.info(f"로그 파일: {log_path}")
    return 0 if vuln == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
