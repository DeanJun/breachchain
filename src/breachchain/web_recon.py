"""HTTP path/directory brute-forcing: given a base URL (typically the port
recon.py found open, e.g. http://<host>:80/), try a wordlist of common
paths and report which ones respond. This is the "attack the web service
itself" capability the ART candidate library doesn't have (see README --
233 safe ART candidates are all post-access shell procedures, none of them
probe an inbound web app).

Deliberately narrow scope: unauthenticated GET requests over a short built-in
wordlist, no vulnerability scanning beyond noting the response. For a lab/test
target you own or have written authorization to test.
"""
from __future__ import annotations

import concurrent.futures
import logging
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("breachchain")

DEFAULT_PATHS = [
    "", "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "dvwa", "backup", "backups", "backup.zip", "backup.sql",
    ".git/HEAD", ".git/config", ".env", "config.php", "config.php.bak",
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "server-status", "server-info", "api", "api/v1", "swagger", "swagger.json",
    "test", "dev", "staging", "uploads", "files", "download", "downloads",
    "console", "manager", "manager/html", "actuator", "actuator/health",
    "debug", "info.php", "phpinfo.php", "index.php~", "index.php.bak",
    ".ssh/id_rsa", "id_rsa", "credentials.txt", "passwords.txt", "secret",
]


@dataclass
class WebHit:
    path: str
    status: int
    length: int
    content_type: str = ""
    looks_like_catchall: bool = False  # response indistinguishable from a nonexistent path


@dataclass
class WebReconResult:
    base_url: str
    attempts: int
    hits: list[WebHit] = field(default_factory=list)
    duration_s: float = 0.0
    catchall_detected: bool = False  # server answers every path the same way (e.g. redirect-everything routers)

    def to_dict(self) -> dict:
        return {**asdict(self), "hits": [asdict(h) for h in self.hits]}

    def real_hits(self) -> list[WebHit]:
        """Hits worth actually looking at -- excludes ones indistinguishable
        from the catch-all baseline (see catchall_detected)."""
        return [h for h in self.hits if not h.looks_like_catchall]


def _probe(base_url: str, path: str, timeout: float) -> WebHit | None:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, headers={"User-Agent": "breachchain-web-recon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096)
            return WebHit(path=path, status=resp.status, length=len(body), content_type=resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as e:
        # 401/403 still means "something is there" -- worth reporting, unlike a plain 404.
        if e.code not in (404,):
            return WebHit(path=path, status=e.code, length=0, content_type="")
        return None
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def web_recon(
    base_url: str,
    paths: list[str] | None = None,
    timeout: float = 5.0,
    max_workers: int = 10,
    log_attempts: bool = False,
) -> WebReconResult:
    paths = paths or DEFAULT_PATHS
    hits: list[WebHit] = []
    t0 = time.monotonic()
    attempted = 0

    # Baseline: probe a path that almost certainly doesn't exist. A server
    # that 404s normally gives None here (nothing to compare against). A
    # server that answers *everything* the same way (catch-all routing --
    # e.g. routers that redirect any unknown path to a login page) gives a
    # real WebHit, which becomes the signature we compare every other hit
    # against so those don't get reported as if they were real findings.
    baseline_path = f"breachchain-recon-baseline-{uuid.uuid4().hex[:12]}"
    baseline = _probe(base_url, baseline_path, timeout)
    if baseline and log_attempts:
        logger.info(f"[기준선] 존재하지 않는 경로도 {baseline.status} {baseline.length}bytes 응답 -> catch-all 서버로 판단, 동일 응답은 걸러냄")

    def _matches_baseline(hit: WebHit) -> bool:
        return baseline is not None and hit.status == baseline.status and hit.length == baseline.length

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, base_url, p, timeout): p for p in paths}
        for future in concurrent.futures.as_completed(futures):
            p = futures[future]
            attempted += 1
            try:
                hit = future.result()
            except Exception as e:
                hit = None
                if log_attempts:
                    logger.info(f"[{attempted}/{len(paths)}] /{p} -> 오류: {e}")
            if hit:
                hit.looks_like_catchall = _matches_baseline(hit)
                hits.append(hit)
                if log_attempts:
                    tag = " (catch-all과 동일, 오탐 가능성)" if hit.looks_like_catchall else ""
                    logger.info(f"[{attempted}/{len(paths)}] /{p} -> {hit.status} ({hit.length} bytes){tag}")
            elif log_attempts:
                logger.info(f"[{attempted}/{len(paths)}] /{p} -> 없음")

    hits.sort(key=lambda h: h.path)
    return WebReconResult(
        base_url=base_url, attempts=attempted, hits=hits,
        duration_s=round(time.monotonic() - t0, 3), catchall_detected=baseline is not None,
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

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="breachchain-web-recon")
    parser.add_argument("base_url", help="e.g. http://192.168.94.131:80")
    parser.add_argument("--paths", help="comma-separated paths (default: built-in wordlist)")
    parser.add_argument("--wordlist", type=Path, help="file with one path per line (overrides --paths/default)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--verbose", action="store_true", help="log every path attempt, not just hits")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "runs" / "web_recon.json")
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()

    log_path = args.log or Path(__file__).resolve().parents[2] / "logs" / f"web_recon_{datetime.now().strftime('%y%m%d_%H%M%S')}.log"
    _setup_logging(log_path)

    if args.wordlist:
        paths = [line.strip() for line in args.wordlist.read_text(encoding="utf-8").splitlines() if line.strip()]
    elif args.paths:
        paths = args.paths.split(",")
    else:
        paths = None

    logger.info(f"웹 경로 스캔 시작: {args.base_url} ({len(paths or DEFAULT_PATHS)}개 경로)")
    result = web_recon(args.base_url, paths, timeout=args.timeout, max_workers=args.workers, log_attempts=args.verbose)

    logger.info(f"시도 {result.attempts}회, {result.duration_s}s 소요")
    if result.catchall_detected:
        logger.info("이 서버는 존재하지 않는 경로에도 응답함(catch-all) — 그 응답과 동일한 결과는 오탐으로 보고 아래 목록에서 제외함")
    real_hits = result.real_hits()
    if real_hits:
        logger.info(f"응답 있는 경로 {len(real_hits)}개:")
        for h in real_hits:
            logger.info(f"  [{h.status}] /{h.path}  ({h.length} bytes, {h.content_type})")
    else:
        logger.info("응답 있는 경로 없음")
    catchall_count = len(result.hits) - len(real_hits)
    if catchall_count:
        logger.info(f"(참고: catch-all 응답과 동일해서 제외한 경로 {catchall_count}개)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"저장: {args.out}")
    logger.info(f"로그 파일: {log_path}")
    return 0 if real_hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
