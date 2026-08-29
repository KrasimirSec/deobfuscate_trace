from __future__ import annotations

import html
import json
from typing import Any


def build_report(
    *,
    result,
    path: str | None,
    sandbox: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "evilbox.report.v1",
        "sample": {
            "path": path,
            "language": result.language,
            "sha256": result.original_sha256,
            "inner_sha256": result.inner_sha256,
            "cluster_sha256": result.cluster_sha256,
        },
        "packer": result.packer,
        "parse_ok": result.parse_ok,
        "warnings": result.warnings,
        "layers": [layer.to_dict() for layer in result.layers],
        "roles": [r.to_dict() for r in result.classification.roles],
        "capabilities": [c.to_dict() for c in result.classification.capabilities],
        "indicators": result.indicators.to_dict(),
        "indicators_by_layer": result.indicators_by_layer,
        "surface_signatures": result.surface.to_dict(),
        "sandbox": sandbox,
    }
    return report


def format_analysis(report: dict[str, Any]) -> str:
    lines: list[str] = []
    roles = report.get("roles") or []
    if roles:
        lines.append("roles:")
        for role in roles:
            lines.append(f"  {role['name']} ({role['score']})")
            for ev in (role.get("evidence") or [])[:2]:
                lines.append(f"    [{ev.get('layer')}] {ev.get('snippet', '')[:100]}")
    else:
        lines.append("roles: (none)")
    caps = report.get("capabilities") or []
    if caps:
        lines.append("capabilities: " + ", ".join(c["id"] for c in caps))
    packer = report.get("packer") or []
    if packer:
        lines.append("packer: " + ", ".join(packer))
    sample = report.get("sample") or {}
    if sample.get("cluster_sha256"):
        lines.append(f"cluster: {sample['cluster_sha256']}")
    surface = (report.get("surface_signatures") or {}).get("items") or []
    if surface:
        lines.append("surface signatures (original layer):")
        for item in surface[:12]:
            lines.append(f"  [{item['kind']}] {item['yara'][:80]}")
            lines.append(f"    why: {item['why']}")
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    roles = "".join(
        f"<li><strong>{esc(r['name'])}</strong> ({esc(r['score'])})</li>" for r in report.get("roles") or []
    ) or "<li>none</li>"
    caps = "".join(f"<li>{esc(c['id'])}</li>" for c in report.get("capabilities") or []) or "<li>none</li>"
    surface = "".join(
        f"<tr><td>{esc(i['kind'])}</td><td><code>{esc(i['yara'])}</code></td><td>{esc(i['why'])}</td></tr>"
        for i in (report.get("surface_signatures") or {}).get("items") or []
    )
    iocs = "".join(
        f"<tr><td>{esc(row['layer'])}</td><td>{esc(row['kind'])}</td><td><code>{esc(row['value'])}</code></td></tr>"
        for row in report.get("indicators_by_layer") or []
    )
    sample = report.get("sample") or {}
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Evilbox report</title>
<style>
body {{ font-family: sans-serif; margin: 1.5rem; color: #111; }}
code {{ font-size: 0.9em; word-break: break-all; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; }}
</style></head><body>
<h1>Evilbox report</h1>
<p>path: {esc(sample.get("path"))}<br>
language: {esc(sample.get("language"))}<br>
sha256: <code>{esc(sample.get("sha256"))}</code><br>
inner: <code>{esc(sample.get("inner_sha256"))}</code><br>
cluster: <code>{esc(sample.get("cluster_sha256"))}</code></p>
<p>packer: {esc(", ".join(report.get("packer") or []))}</p>
<h2>Roles</h2><ul>{roles}</ul>
<h2>Capabilities</h2><ul>{caps}</ul>
<h2>Surface signatures (original layer)</h2>
<table><tr><th>kind</th><th>YARA needle</th><th>why</th></tr>{surface}</table>
<h2>Indicators by layer</h2>
<table><tr><th>layer</th><th>kind</th><th>value</th></tr>{iocs}</table>
</body></html>
"""


def dump_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"
