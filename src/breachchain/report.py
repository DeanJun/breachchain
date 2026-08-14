"""Renders an HTML report from a scenario run: step-by-step log, final
accumulated state, and ATT&CK coverage summary. Self-contained (no external
assets) so it opens standalone and prints cleanly to PDF from a browser.
"""
from __future__ import annotations

import html
import sys
from datetime import datetime
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from breachchain.executor import ExecutionResult
    from breachchain.state import ScenarioState
else:
    from .executor import ExecutionResult
    from .state import ScenarioState

_STYLE = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --border: #ddd;
  --pass: #1a7f37; --fail: #b3261e; --code-bg: #f6f8fa; --accent: #f5f5f5;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, Segoe UI, "Malgun Gothic", Helvetica, Arial, sans-serif;
  color: var(--fg); background: var(--bg);
  max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; line-height: 1.5;
}
h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
.subtitle { color: var(--muted); margin-top: 0; margin-bottom: 1.5rem; font-size: 0.9rem; }
h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
h3 { font-size: 1rem; margin-top: 1.25rem; margin-bottom: 0.4rem; }
.summary { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0; }
.stat { background: var(--accent); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 1rem; }
.stat .value { font-size: 1.3rem; font-weight: 600; }
.stat .label { font-size: 0.8rem; color: var(--muted); }
.step { border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 0.8rem; }
.step-title { font-weight: 600; }
.badge { display: inline-block; font-size: 0.75rem; font-weight: 700; padding: 0.1rem 0.5rem; border-radius: 4px; margin-left: 0.5rem; }
.badge.pass { background: #e6f4ea; color: var(--pass); }
.badge.fail { background: #fbeae9; color: var(--fail); }
.meta { color: var(--muted); font-size: 0.85rem; margin: 0.3rem 0; }
code, .cmd { font-family: SFMono-Regular, Consolas, Menlo, monospace; font-size: 0.85rem; }
.cmd { display: block; background: var(--code-bg); padding: 0.4rem 0.6rem; border-radius: 4px; overflow-x: auto; }
pre { background: var(--code-bg); padding: 0.6rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
pre.err { background: #fbeae9; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; font-size: 0.9rem; }
th, td { border: 1px solid var(--border); padding: 0.4rem 0.6rem; text-align: left; }
th { background: var(--accent); }
ul { margin: 0.3rem 0; padding-left: 1.3rem; }
@media print {
  body { margin: 0; max-width: 100%; }
  .step { break-inside: avoid; }
}
"""


def _esc(text: str) -> str:
    return html.escape(str(text))


_MAX_OUTPUT_LINES = 15


def _render_output(stdout: str, success: bool) -> str:
    """Full output for failures (need it to diagnose). For successes, some ART
    commands dump hundreds of lines (e.g. `ip tcp_metrics show`) that just
    prove the command ran -- truncate those so the report stays readable.
    """
    lines = stdout.splitlines()
    if success and len(lines) > _MAX_OUTPUT_LINES:
        shown = "\n".join(lines[:_MAX_OUTPUT_LINES])
        return f"<pre>{_esc(shown)}\n... ({len(lines) - _MAX_OUTPUT_LINES}줄 생략, 총 {len(lines)}줄)</pre>"
    return f"<pre>{_esc(stdout)}</pre>"


def render_report_html(
    results: list[ExecutionResult],
    state: ScenarioState,
    coverage: dict,
    scenario_name: str = "breachchain scenario run",
    step_tactics: list[str] | None = None,
    recon: dict | None = None,
    bruteforce: dict | None = None,
    web_recon: dict | None = None,
    vuln_scan: dict | None = None,
    kisa: dict | None = None,
    fingerprint: dict | None = None,
) -> str:
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    parts = [
        "<!doctype html>",
        "<html lang=\"ko\"><head><meta charset=\"utf-8\">",
        f"<title>{_esc(scenario_name)}</title>",
        f"<style>{_STYLE}</style></head><body>",
        f"<h1>{_esc(scenario_name)}</h1>",
        f"<p class=\"subtitle\">생성 시각: {_esc(generated_at)}</p>",
        "<h2>요약</h2>",
        "<div class=\"summary\">",
        f"<div class=\"stat\"><div class=\"value\">{total}</div><div class=\"label\">실행 단계</div></div>",
        f"<div class=\"stat\"><div class=\"value\">{succeeded}/{total}</div><div class=\"label\">성공</div></div>",
        f"<div class=\"stat\"><div class=\"value\">{coverage['technique_count']}</div><div class=\"label\">ATT&amp;CK 커버 기법 수</div></div>",
        "</div>",
    ]

    if recon is not None:
        open_ports = recon.get("open_ports", [])
        parts.append("<h2>정찰: 열린 포트</h2>")
        parts.append(f"<p class=\"meta\">대상: <code>{_esc(recon.get('target', ''))}</code> &middot; 방법: {_esc(recon.get('method', ''))} &middot; 열린 포트 {len(open_ports)}개</p>")
        if open_ports:
            parts.append("<table><tr><th>포트</th><th>서비스</th><th>배너</th></tr>")
            for p in open_ports:
                parts.append(
                    f"<tr><td>{p.get('port')}/{_esc(p.get('protocol', 'tcp'))}</td>"
                    f"<td>{_esc(p.get('service', ''))}</td><td>{_esc(p.get('banner', ''))}</td></tr>"
                )
            parts.append("</table>")

    if bruteforce is not None:
        hits = bruteforce.get("hits", [])
        parts.append("<h2>초기 접근: SSH 브루트포싱</h2>")
        parts.append(
            f"<p class=\"meta\">대상: <code>{_esc(bruteforce.get('target', ''))}:{bruteforce.get('port', '')}</code> "
            f"&middot; 시도 {bruteforce.get('attempts', 0)}회 &middot; {bruteforce.get('duration_s', 0)}s</p>"
        )
        if hits:
            parts.append(f"<p><span class=\"badge fail\">취약</span> 자격정보 {len(hits)}개 발견</p>")
            parts.append("<table><tr><th>사용자</th><th>비밀번호</th></tr>")
            for h in hits:
                parts.append(f"<tr><td>{_esc(h.get('user'))}</td><td>{_esc(h.get('password'))}</td></tr>")
            parts.append("</table>")
        else:
            parts.append("<p><span class=\"badge pass\">양호</span> 시도한 목록에서 유효한 자격정보 없음</p>")

    if fingerprint is not None:
        parts.append("<h2>대상 식별 (OS/펌웨어)</h2>")
        if fingerprint.get("is_likely_embedded"):
            parts.append("<p><span class=\"badge fail\">IoT/임베디드 추정</span></p>")
        parts.append("<table>")
        rows = [
            ("OS", fingerprint.get("os_release") or "(확인 불가)"),
            ("커널", fingerprint.get("kernel") or "(확인 불가)"),
            ("아키텍처", fingerprint.get("cpu_arch") or "(확인 불가)"),
            ("CPU", fingerprint.get("cpu_model") or "(확인 불가)"),
            ("보드 모델", fingerprint.get("board_model") or "(해당 없음/확인 불가)"),
        ]
        for label, value in rows:
            parts.append(f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>")
        parts.append("</table>")

    if web_recon is not None:
        all_hits = web_recon.get("hits", [])
        hits = [h for h in all_hits if not h.get("looks_like_catchall")]
        catchall_count = len(all_hits) - len(hits)
        parts.append("<h2>정찰: 웹 경로 스캔</h2>")
        parts.append(
            f"<p class=\"meta\">대상: <code>{_esc(web_recon.get('base_url', ''))}</code> "
            f"&middot; 시도 {web_recon.get('attempts', 0)}회 &middot; {web_recon.get('duration_s', 0)}s</p>"
        )
        if web_recon.get("catchall_detected"):
            parts.append(
                "<p class=\"meta\">이 서버는 존재하지 않는 경로에도 응답함(catch-all 라우팅) — "
                f"동일한 응답을 준 경로 {catchall_count}개는 오탐으로 판단해 아래 목록에서 제외함</p>"
            )
        if hits:
            parts.append(f"<p><span class=\"badge fail\">주의</span> 응답 있는 경로 {len(hits)}개 발견</p>")
            parts.append("<table><tr><th>상태코드</th><th>경로</th><th>크기</th><th>Content-Type</th></tr>")
            for h in hits:
                parts.append(
                    f"<tr><td>{h.get('status')}</td><td>/{_esc(h.get('path'))}</td>"
                    f"<td>{h.get('length')}</td><td>{_esc(h.get('content_type', ''))}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p><span class=\"badge pass\">양호</span> 시도한 목록에서 노출된 경로 없음</p>")

    if vuln_scan is not None:
        matches = vuln_scan.get("matches", [])
        total_cves = sum(len(m.get("cves", [])) for m in matches)
        parts.append("<h2>취약점: 버전 기반 CVE 매칭</h2>")
        parts.append(
            "<p class=\"meta\">배너에서 인식한 제품/버전을 NVD에 조회한 결과입니다. "
            "CVE가 있다고 해서 실제로 뚫린다는 뜻은 아니며(배포판 백포트/설정에 따라 다름), "
            "매칭 자체가 참고용 휴리스틱입니다.</p>"
        )
        if total_cves:
            parts.append(f"<p><span class=\"badge fail\">주의</span> CVE {total_cves}건 발견</p>")
        for m in matches:
            if not m.get("product"):
                parts.append(f"<p class=\"meta\">{m.get('port')}/tcp: {_esc(m.get('note', ''))}</p>")
                continue
            parts.append(f"<h3>{m.get('port')}/tcp — {_esc(m.get('product'))} {_esc(m.get('version'))}</h3>")
            cves = m.get("cves", [])
            if cves:
                parts.append("<table><tr><th>CVE</th><th>심각도</th><th>점수</th><th>설명</th></tr>")
                for c in cves:
                    parts.append(
                        f"<tr><td>{_esc(c.get('cve_id'))}</td><td>{_esc(c.get('severity', ''))}</td>"
                        f"<td>{c.get('score', '')}</td><td>{_esc(c.get('description', ''))}</td></tr>"
                    )
                parts.append("</table>")
            else:
                parts.append("<p><span class=\"badge pass\">양호</span> 매칭된 CVE 없음</p>")

    if kisa is not None:
        items = kisa.get("results", [])
        good = sum(1 for r in items if r.get("final_result") == "GOOD")
        vuln = sum(1 for r in items if r.get("final_result") == "VULNERABLE")
        manual = sum(1 for r in items if r.get("final_result") == "MANUAL")
        parts.append("<h2>KISA CIIP 기술적 취약점 진단</h2>")
        parts.append(
            f"<p class=\"meta\">대상: <code>{_esc(kisa.get('target', ''))}</code> "
            f"&middot; 플랫폼: {_esc(kisa.get('platform', ''))} &middot; 총 {len(items)}개 항목 "
            f"(2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드 기준)</p>"
        )
        parts.append("<div class=\"summary\">")
        parts.append(f"<div class=\"stat\"><div class=\"value\">{good}</div><div class=\"label\">양호</div></div>")
        parts.append(f"<div class=\"stat\"><div class=\"value\">{vuln}</div><div class=\"label\">취약</div></div>")
        parts.append(f"<div class=\"stat\"><div class=\"value\">{manual}</div><div class=\"label\">수동진단</div></div>")
        parts.append("</div>")
        vuln_items = [r for r in items if r.get("final_result") == "VULNERABLE"]
        if vuln_items:
            parts.append("<h3>취약 항목</h3>")
            for r in vuln_items:
                guideline = r.get("guideline", {})
                parts.append("<div class=\"step\">")
                parts.append(
                    f"<div class=\"step-title\">{_esc(r.get('item_id'))}: {_esc(r.get('item_name'))}"
                    f"<span class=\"badge fail\">취약</span></div>"
                )
                parts.append(f"<div class=\"meta\">{_esc(r.get('summary', ''))}</div>")
                if guideline.get("remediation"):
                    parts.append(f"<p><strong>조치방법:</strong> {_esc(guideline['remediation'])}</p>")
                parts.append("</div>")
        manual_items = [r for r in items if r.get("final_result") == "MANUAL"]
        if manual_items:
            parts.append("<h3>수동진단 필요 항목</h3><ul>")
            for r in manual_items:
                parts.append(f"<li>{_esc(r.get('item_id'))}: {_esc(r.get('item_name'))} — {_esc(r.get('summary', ''))}</li>")
            parts.append("</ul>")

    parts.append("<h2>실행 체인</h2>")
    current_tactic = None
    for i, r in enumerate(results, start=1):
        if step_tactics is not None:
            tactic = step_tactics[i - 1]
            if tactic != current_tactic:
                parts.append(f"<h3>전술: {_esc(tactic)}</h3>")
                current_tactic = tactic
        status = "성공" if r.success else "실패"
        badge_cls = "pass" if r.success else "fail"
        parts.append("<div class=\"step\">")
        parts.append(
            f"<div class=\"step-title\">Step {i}: [{_esc(r.technique_id)}] {_esc(r.display_name)}"
            f"<span class=\"badge {badge_cls}\">{status}</span></div>"
        )
        parts.append(f"<div class=\"meta\">대상: <code>{_esc(r.target_name)}</code> &middot; 소요 시간: {r.duration_s}s</div>")
        parts.append(f"<span class=\"cmd\">{_esc(r.command.strip())}</span>")
        if r.stdout.strip():
            parts.append(_render_output(r.stdout.strip(), r.success))
        if not r.success and r.stderr.strip():
            parts.append(f"<pre class=\"err\">{_esc(r.stderr.strip())}</pre>")
        parts.append("</div>")

    parts.append("<h2>누적 상태</h2>")
    parts.append("<h3>확보 자산</h3><ul>")
    for a in state.assets:
        parts.append(f"<li><code>{_esc(a.name)}</code> ({_esc(a.kind)}) — {_esc(a.discovered_via)}에서 발견</li>")
    parts.append("</ul>")
    parts.append("<h3>확보 자격정보</h3><ul>")
    for c in state.credentials:
        parts.append(
            f"<li><code>{_esc(c.identity)}</code> (출처: <code>{_esc(c.source_asset)}</code>) — {_esc(c.discovered_via)}에서 발견</li>"
        )
    parts.append("</ul>")
    parts.append("<h3>획득 접근 권한</h3><ul>")
    for a in state.access:
        parts.append(f"<li><code>{_esc(a.asset)}</code>에 대한 <code>{_esc(a.level)}</code> 권한 — {_esc(a.discovered_via)}로 획득</li>")
    parts.append("</ul>")

    parts.append("<h2>ATT&amp;CK 커버리지</h2>")
    parts.append("<table><tr><th>기법</th><th>이름</th><th>시도</th><th>성공</th><th>대상</th></tr>")
    for t in coverage["techniques"]:
        targets = ", ".join(t["targets"])
        parts.append(
            f"<tr><td>{_esc(t['technique_id'])}</td><td>{_esc(t['display_name'])}</td>"
            f"<td>{t['attempts']}</td><td>{t['successes']}</td><td>{_esc(targets)}</td></tr>"
        )
    parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


def run_timestamp() -> str:
    return datetime.now().strftime("%y%m%d_%H%M%S")


def report_filename(timestamp: str, prefix: str = "report") -> str:
    return f"{prefix}_{timestamp}.html"


def save_report(report_html: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_html, encoding="utf-8")
