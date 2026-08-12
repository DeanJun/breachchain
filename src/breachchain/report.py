"""Renders an HTML report from a scenario run: step-by-step log, final
accumulated state, and ATT&CK coverage summary. Self-contained (no external
assets) so it opens standalone and prints cleanly to PDF from a browser.
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from .executor import ExecutionResult
from .state import ScenarioState

_STYLE = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --border: #ddd;
  --pass: #1a7f37; --fail: #b3261e; --code-bg: #f6f8fa; --accent: #f5f5f5;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
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
@media (prefers-color-scheme: dark) {
  :root { --bg: #1e1e1e; --fg: #e6e6e6; --muted: #999; --border: #3a3a3a; --code-bg: #2a2a2a; --accent: #2a2a2a; }
}
@media print {
  body { margin: 0; max-width: 100%; }
  .step { break-inside: avoid; }
}
"""


def _esc(text: str) -> str:
    return html.escape(str(text))


def render_report_html(
    results: list[ExecutionResult],
    state: ScenarioState,
    coverage: dict,
    scenario_name: str = "breachchain scenario run",
) -> str:
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    parts = [
        "<!doctype html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<title>{_esc(scenario_name)}</title>",
        f"<style>{_STYLE}</style></head><body>",
        f"<h1>{_esc(scenario_name)}</h1>",
        f"<p class=\"subtitle\">Generated {_esc(generated_at)}</p>",
        "<h2>Summary</h2>",
        "<div class=\"summary\">",
        f"<div class=\"stat\"><div class=\"value\">{total}</div><div class=\"label\">Steps executed</div></div>",
        f"<div class=\"stat\"><div class=\"value\">{succeeded}/{total}</div><div class=\"label\">Succeeded</div></div>",
        f"<div class=\"stat\"><div class=\"value\">{coverage['technique_count']}</div><div class=\"label\">ATT&amp;CK techniques covered</div></div>",
        "</div>",
    ]

    parts.append("<h2>Execution Chain</h2>")
    for i, r in enumerate(results, start=1):
        status = "PASS" if r.success else "FAIL"
        badge_cls = "pass" if r.success else "fail"
        parts.append("<div class=\"step\">")
        parts.append(
            f"<div class=\"step-title\">Step {i}: [{_esc(r.technique_id)}] {_esc(r.display_name)}"
            f"<span class=\"badge {badge_cls}\">{status}</span></div>"
        )
        parts.append(f"<div class=\"meta\">Target: <code>{_esc(r.target_name)}</code> &middot; Duration: {r.duration_s}s</div>")
        parts.append(f"<span class=\"cmd\">{_esc(r.command.strip())}</span>")
        if r.stdout.strip():
            parts.append(f"<pre>{_esc(r.stdout.strip())}</pre>")
        if not r.success and r.stderr.strip():
            parts.append(f"<pre class=\"err\">{_esc(r.stderr.strip())}</pre>")
        parts.append("</div>")

    parts.append("<h2>Accumulated State</h2>")
    parts.append("<h3>Assets</h3><ul>")
    for a in state.assets:
        parts.append(f"<li><code>{_esc(a.name)}</code> ({_esc(a.kind)}) — discovered via {_esc(a.discovered_via)}</li>")
    parts.append("</ul>")
    parts.append("<h3>Credentials</h3><ul>")
    for c in state.credentials:
        parts.append(
            f"<li><code>{_esc(c.identity)}</code> from <code>{_esc(c.source_asset)}</code> — discovered via {_esc(c.discovered_via)}</li>"
        )
    parts.append("</ul>")
    parts.append("<h3>Access Gained</h3><ul>")
    for a in state.access:
        parts.append(f"<li><code>{_esc(a.level)}</code> on <code>{_esc(a.asset)}</code> — via {_esc(a.discovered_via)}</li>")
    parts.append("</ul>")

    parts.append("<h2>ATT&amp;CK Coverage</h2>")
    parts.append("<table><tr><th>Technique</th><th>Name</th><th>Attempts</th><th>Successes</th><th>Targets</th></tr>")
    for t in coverage["techniques"]:
        targets = ", ".join(t["targets"])
        parts.append(
            f"<tr><td>{_esc(t['technique_id'])}</td><td>{_esc(t['display_name'])}</td>"
            f"<td>{t['attempts']}</td><td>{t['successes']}</td><td>{_esc(targets)}</td></tr>"
        )
    parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


def report_filename(prefix: str = "report") -> str:
    return f"{prefix}_{datetime.now().strftime('%y%m%d_%H%M')}.html"


def save_report(report_html: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_html, encoding="utf-8")
