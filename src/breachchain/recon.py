"""Initial-access recon: given just an IP, find open ports/services before any
credentials exist. Runs entirely locally (no target auth needed) -- this is
the step that was missing when the whole pipeline assumed SSH access was
already granted (see README section 7-0 / the "IP만 알고 있을 때" discussion).

Uses nmap if it's on PATH (richer service/version detection); otherwise falls
back to a pure-Python threaded TCP connect scan + banner grab, so recon works
without requiring an extra install.
"""
from __future__ import annotations

import concurrent.futures
import http.client
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
    5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8443, 8888, 9000,
    9090, 9200, 9300, 11211, 15672, 27017,
]

# IoT/임베디드 장비에서 흔히 열려 있는 포트 -- 서버용 COMMON_PORTS엔 없던 것들
# (텔넷 관리 콘솔, 카메라 RTSP 스트림, MQTT 브로커, 산업제어 프로토콜, 라우터
# 관리 포트, TR-069 원격관리 등). 기본 스캔에 포함시켜 IoT 대상을 더 잘 잡는다.
IOT_PORTS = [
    23,      # 텔넷 -- 라우터/카메라/DVR 관리 콘솔에 여전히 흔함 (COMMON_PORTS와 겹침)
    554,     # RTSP -- IP 카메라 비디오 스트림
    1883,    # MQTT
    8883,    # MQTT over TLS
    5683,    # CoAP (UDP가 원칙이지만 TCP 바리안트도 존재)
    502,     # Modbus (산업제어)
    102,     # Siemens S7comm (산업제어 PLC)
    20000,   # DNP3 (산업제어)
    7547,    # TR-069/CWMP -- ISP가 라우터 원격관리에 쓰는 포트, 실제 봇넷 표적이 됐던 이력 있음
    8291,    # Mikrotik Winbox
    37777,   # 다후아(Dahua)류 DVR/NVR 관리 포트
    9999,    # 일부 공유기/IoT 웹 관리 포트
]


def default_ports() -> list[int]:
    """COMMON_PORTS + IOT_PORTS 합집합, 순서 보존."""
    seen = set()
    merged = []
    for p in COMMON_PORTS + IOT_PORTS:
        if p not in seen:
            seen.add(p)
            merged.append(p)
    return merged

# Web servers don't send anything until spoken to, unlike SSH/FTP/SMTP which
# banner first -- a raw socket recv() on these just times out with nothing.
# Need an actual HTTP HEAD to read the Server header (e.g. "nginx/1.18.0").
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9000, 9090}
HTTPS_PORTS = {443, 8443}


@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""


@dataclass
class ReconResult:
    target: str
    method: str  # "nmap" | "socket"
    open_ports: list[OpenPort] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"target": self.target, "method": self.method, "open_ports": [asdict(p) for p in self.open_ports]}


def _grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                return ""
    except OSError:
        return ""


def _grab_http_banner(host: str, port: int, timeout: float) -> str:
    """Send a real HTTP HEAD and return the Server header (e.g. "nginx/1.18.0
    (Ubuntu)"), which is what vuln_scan.py's version regexes expect. Falls
    back to empty string on any error (self-signed TLS, non-HTTP service on
    a "likely HTTP" port, connection reset, etc.) -- caller falls back to
    the raw socket banner in that case.
    """
    conn_cls = http.client.HTTPSConnection if port in HTTPS_PORTS else http.client.HTTPConnection
    conn = None
    try:
        conn = conn_cls(host, port, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "breachchain-recon"})
        resp = conn.getresponse()
        return resp.getheader("Server", "") or ""
    except Exception:
        return ""
    finally:
        if conn:
            conn.close()


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _scan_socket(host: str, ports: list[int], timeout: float, max_workers: int) -> list[OpenPort]:
    def check(port: int) -> OpenPort | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            return None
        banner = _grab_http_banner(host, port, timeout) if port in HTTP_PORTS else ""
        if not banner:
            banner = _grab_banner(host, port, timeout)
        return OpenPort(port=port, service=_service_name(port), banner=banner)

    open_ports: list[OpenPort] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for result in pool.map(check, ports):
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda p: p.port)


def _scan_nmap(host: str, ports: list[int], timeout: float) -> list[OpenPort] | None:
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return None
    port_arg = ",".join(str(p) for p in ports)
    try:
        proc = subprocess.run(
            [nmap_bin, "-Pn", "-sV", "-p", port_arg, host],
            capture_output=True, text=True, timeout=max(30, int(timeout * len(ports))),
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    open_ports = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if "/tcp" not in line or "open" not in line:
            continue
        parts = line.split()
        port = int(parts[0].split("/")[0])
        service = parts[2] if len(parts) > 2 else ""
        banner = " ".join(parts[3:]) if len(parts) > 3 else ""
        open_ports.append(OpenPort(port=port, service=service, banner=banner))
    return open_ports


def scan(host: str, ports: list[int] | None = None, timeout: float = 1.5, max_workers: int = 100) -> ReconResult:
    ports = ports or default_ports()
    nmap_result = _scan_nmap(host, ports, timeout)
    if nmap_result is not None:
        return ReconResult(target=host, method="nmap", open_ports=nmap_result)
    return ReconResult(target=host, method="socket", open_ports=_scan_socket(host, ports, timeout, max_workers))


def main() -> int:
    import argparse
    import json

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="breachchain-recon")
    parser.add_argument("host")
    parser.add_argument("--ports", help="comma-separated port list (default: common ports)")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "runs" / "recon.json")
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    result = scan(args.host, ports, timeout=args.timeout)

    print(f"[{result.method}] {result.target}: 열린 포트 {len(result.open_ports)}개")
    for p in result.open_ports:
        print(f"  {p.port}/tcp  {p.service}  {p.banner[:60]}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
