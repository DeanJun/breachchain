"""Minimal version-based vulnerability matching: takes the service banners
recon.py already grabs (e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16") and
looks up known CVEs for that product/version via the public NVD REST API.

Deliberately narrow scope, explicitly NOT a real vulnerability scanner:
- No exploit verification -- a CVE existing for a version string doesn't mean
  the target is actually exploitable (distro backports, config, etc. all matter).
- Banner-string version parsing is a heuristic (regex), not authoritative.
- NVD's public API is rate-limited (~5 requests/30s without an API key), so
  this is fine for a handful of services from one recon run, not a fleet scan.
This is "does the banner version have CVEs on record", not "is this exploitable".
"""
from __future__ import annotations

import json
import logging
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("breachchain")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (regex, product name) -- checked in order, first match wins. Keep patterns
# specific (anchored to known banner shapes) rather than trying to parse
# arbitrary banners generically.
_BANNER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"OpenSSH[_/](\d+\.\d+(?:p\d+)?)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"nginx[/ ](\d+\.\d+\.\d+)", re.IGNORECASE), "nginx"),
    (re.compile(r"Apache[/ ](\d+\.\d+\.\d+)", re.IGNORECASE), "Apache HTTP Server"),
    (re.compile(r"vsFTPd[ _](\d+\.\d+\.\d+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD[ /](\d+\.\d+\.\d+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"MySQL[ /](\d+\.\d+\.\d+)", re.IGNORECASE), "MySQL"),
    (re.compile(r"PostgreSQL[ ,](\d+\.\d+)", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Microsoft-IIS[/ ](\d+\.\d+)", re.IGNORECASE), "IIS"),
]


@dataclass
class CveHit:
    cve_id: str
    description: str
    severity: str = ""
    score: float | None = None


@dataclass
class VersionMatch:
    port: int
    service: str
    banner: str
    product: str | None
    version: str | None
    cves: list[CveHit] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {**{k: v for k, v in asdict(self).items() if k != "cves"}, "cves": [asdict(c) for c in self.cves]}


def parse_banner(banner: str) -> tuple[str, str] | None:
    for pattern, product in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            return product, m.group(1)
    return None


def query_nvd(product: str, version: str, timeout: float = 30.0, max_results: int = 10) -> list[CveHit]:
    query = urllib.parse.urlencode({"keywordSearch": f"{product} {version}", "resultsPerPage": max_results})
    url = f"{NVD_API}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "breachchain-vuln-scan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        logger.info(f"  NVD 조회 실패 ({product} {version}): {e}")
        return []

    hits = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), descs[0]["value"] if descs else "")
        metrics = cve.get("metrics", {})
        severity, score = "", None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = metrics[key][0].get("baseSeverity", cvss.get("baseSeverity", ""))
                break
        hits.append(CveHit(cve_id=cve_id, description=desc[:300], severity=severity, score=score))
    return hits


def scan_recon(recon: dict, delay_between_queries: float = 6.0) -> list[VersionMatch]:
    """Given a recon.py ReconResult dict (open_ports with service/banner),
    parse each banner and look up CVEs. Sleeps between NVD queries to stay
    under the public API's unauthenticated rate limit.
    """
    matches: list[VersionMatch] = []
    open_ports = recon.get("open_ports", [])
    for i, p in enumerate(open_ports):
        banner = p.get("banner", "") or p.get("service", "")
        parsed = parse_banner(banner)
        if not parsed:
            matches.append(VersionMatch(
                port=p.get("port"), service=p.get("service", ""), banner=banner,
                product=None, version=None, note="배너에서 제품/버전을 인식하지 못함 (매칭 패턴 없음)",
            ))
            continue
        product, version = parsed
        logger.info(f"  {p.get('port')}/tcp: {product} {version} -> NVD 조회 중...")
        if i > 0:
            time.sleep(delay_between_queries)
        cves = query_nvd(product, version)
        matches.append(VersionMatch(port=p.get("port"), service=p.get("service", ""), banner=banner, product=product, version=version, cves=cves))
    return matches


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

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="breachchain-vuln-scan")
    parser.add_argument("--recon", type=Path, default=Path(__file__).resolve().parents[2] / "runs" / "recon.json", help="recon.py output to read banners from")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "runs" / "vuln_scan.json")
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()

    log_path = args.log or Path(__file__).resolve().parents[2] / "logs" / f"vuln_scan_{datetime.now().strftime('%y%m%d_%H%M%S')}.log"
    _setup_logging(log_path)

    if not args.recon.exists():
        logger.info(f"{args.recon} 없음. 먼저 recon.py를 실행하세요.")
        return 1
    recon = json.loads(args.recon.read_text(encoding="utf-8"))

    logger.info(f"버전 매칭 시작: {recon.get('target')} ({len(recon.get('open_ports', []))}개 포트)")
    matches = scan_recon(recon)

    total_cves = sum(len(m.cves) for m in matches)
    logger.info(f"완료: {len(matches)}개 포트 확인, CVE {total_cves}건 발견")
    for m in matches:
        if m.product:
            logger.info(f"  {m.port}/tcp {m.product} {m.version}: CVE {len(m.cves)}건")
            for c in m.cves[:5]:
                logger.info(f"    {c.cve_id} [{c.severity or '?'} {c.score or ''}] {c.description[:100]}")
        else:
            logger.info(f"  {m.port}/tcp: {m.note}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"target": recon.get("target"), "matches": [m.to_dict() for m in matches]}, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"저장: {args.out}")
    logger.info(f"로그 파일: {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
