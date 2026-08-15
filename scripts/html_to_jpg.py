"""Renders breachchain's HTML reports to JPG for quick sharing (screenshots,
slides) without opening a browser by hand. Local convenience tool only --
not part of the pipeline, not imported by anything else.

Uses whatever Chromium-based browser is installed (Edge or Chrome) in
headless screenshot mode, since that's already on this machine and avoids
adding a Playwright/Selenium dependency for a one-off conversion. Headless
Chromium only writes PNG, so Pillow does the PNG -> JPG step.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageChops

_BROWSER_CANDIDATES = [
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def _find_browser() -> str:
    for candidate in _BROWSER_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    raise FileNotFoundError(
        "Edge나 Chrome을 못 찾았습니다. _BROWSER_CANDIDATES에 설치 경로를 추가하세요."
    )


def _autocrop_whitespace(img: Image.Image) -> Image.Image:
    """Chrome headless screenshots the whole --window-size viewport, not just
    the rendered content -- reports are variable-length, so we capture a
    generously tall window and trim the trailing white margin back off
    instead of trying to predict the exact page height up front.
    """
    bg = Image.new("RGB", img.size, (255, 255, 255))
    diff = ImageChops.difference(img, bg)
    bbox = diff.getbbox()
    if bbox is None:
        return img
    # Small margin so text isn't flush against the edge.
    left, top, right, bottom = bbox
    return img.crop((0, 0, img.width, min(img.height, bottom + 20)))


def html_to_jpg(html_path: Path, jpg_path: Path, width: int = 1000, quality: int = 90) -> None:
    browser = _find_browser()
    html_uri = html_path.resolve().as_uri()

    with tempfile.TemporaryDirectory() as tmp:
        png_path = Path(tmp) / "shot.png"
        subprocess.run(
            [
                browser,
                "--headless=new",
                "--disable-gpu",
                f"--window-size={width},20000",
                "--screenshot=" + str(png_path),
                "--default-background-color=FFFFFFFF",
                "--force-device-scale-factor=1",
                "--virtual-time-budget=5000",
                html_uri,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        img = Image.open(png_path).convert("RGB")
        img = _autocrop_whitespace(img)
        jpg_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(jpg_path, "JPEG", quality=quality)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="html_to_jpg")
    parser.add_argument("html", type=Path, nargs="?", help="HTML report path (default: latest reports/report_*.html)")
    parser.add_argument("--out", type=Path, help="output .jpg path (default: same name under jpg_exports/)")
    parser.add_argument("--width", type=int, default=1000)
    parser.add_argument("--quality", type=int, default=90)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    html_path = args.html
    if html_path is None:
        candidates = sorted((repo_root / "reports").glob("report_*.html"))
        if not candidates:
            print("reports/ 안에 report_*.html이 없습니다. 경로를 직접 지정하세요.")
            return 1
        html_path = candidates[-1]
        print(f"대상 리포트 자동 선택: {html_path}")

    out_path = args.out or (repo_root / "jpg_exports" / (html_path.stem + ".jpg"))

    html_to_jpg(html_path, out_path, width=args.width, quality=args.quality)
    print(f"저장: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
