"""Embedded Dark Fluoroscopy single-page Context Token Flamegraph & Outbound Header Inspector."""

from __future__ import annotations

import json
from typing import Any


def render_inspector_html(dataset: dict[str, Any], *, live_poll: bool = False) -> str:
    payload_json = json.dumps(dataset, ensure_ascii=False).replace("</", "<\\/")
    poll_js = "true" if live_poll else "false"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>agent-xray — Context Token Flamegraph &amp; Outbound Egress Inspector</title>
<style>
  :root {{
    --bg: #070b11;
    --panel: #0d141f;
    --panel-alt: #121c2b;
    --border: #1d2b3e;
    --ink: #eef4fb;
    --muted: #8499b3;
    --c-sys: #38bdf8;
    --c-rules: #a78bfa;
    --c-mcp: #f43f5e;
    --c-results: #34d399;
    --c-conv: #fbbf24;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", system-ui, sans-serif;
    font-size: 13px;
    line-height: 1.45;
    font-variant-numeric: tabular-nums;
  }}
  .mono {{
    font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace;
  }}
  header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 15px 24px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .beam-mark {{
    width: 30px;
    height: 30px;
    border-radius: 7px;
    background: linear-gradient(135deg, rgba(56,189,248,0.2), rgba(244,63,94,0.22));
    border: 1px solid rgba(56,189,248,0.45);
    display: grid;
    place-items: center;
    font-weight: 700;
    color: var(--c-sys);
  }}
  .brand h1 {{
    font-size: 16px;
    font-weight: 600;
    letter-spacing: -0.01em;
  }}
  .brand p {{
    font-size: 12px;
    color: var(--muted);
  }}
  .kpis {{
    display: flex;
    gap: 24px;
    align-items: baseline;
  }}
  .kpi {{
    text-align: right;
  }}
  .kpi .val {{
    font-size: 16px;
    font-weight: 600;
  }}
  .kpi .lbl {{
    font-size: 11px;
    color: var(--muted);
  }}
  main {{
    display: grid;
    grid-template-columns: 1.42fr 1fr;
    gap: 16px;
    padding: 18px 24px 24px;
    max-width: 1440px;
    margin: 0 auto;
  }}
  .surface {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }}
  .surface-head {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(18, 28, 43, 0.55);
  }}
  .surface-head h2 {{
    font-size: 13px;
    font-weight: 600;
  }}
  .legend {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11.5px;
    color: var(--muted);
  }}
  .legend span {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .swatch {{
    width: 9px;
    height: 9px;
    border-radius: 2px;
    display: inline-block;
  }}
  .flame-rows {{
    padding: 10px 14px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}
  .turn-row {{
    padding: 9px 11px;
    border-radius: 8px;
    border: 1px solid transparent;
    background: rgba(18, 28, 43, 0.38);
    cursor: pointer;
    transition: border-color 120ms ease, background 120ms ease;
  }}
  .turn-row.active {{
    border-color: rgba(56, 189, 248, 0.55);
    background: rgba(56, 189, 248, 0.08);
  }}
  .turn-row.blocked {{
    border-color: rgba(244, 63, 94, 0.55);
    background: rgba(244, 63, 94, 0.09);
  }}
  .turn-meta {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 6px;
    gap: 10px;
  }}
  .turn-title {{
    font-size: 12px;
    color: var(--ink);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  .turn-toks {{
    font-size: 11.5px;
    color: var(--muted);
    flex-shrink: 0;
  }}
  .bar-track {{
    display: flex;
    height: 16px;
    width: 100%;
    background: #090f17;
    border-radius: 4px;
    overflow: hidden;
    gap: 1px;
  }}
  .seg {{ height: 100%; min-width: 2px; }}
  .right-stack {{
    display: flex;
    flex-direction: column;
    gap: 16px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  th, td {{
    text-align: left;
    padding: 8px 14px;
    border-bottom: 1px solid rgba(29, 43, 62, 0.7);
  }}
  th {{
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
  }}
  td.num, th.num {{ text-align: right; }}
  .pill {{
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 10.5px;
    font-weight: 600;
  }}
  .pill-rose {{ background: rgba(244,63,94,0.16); color: #fb7185; }}
  .pill-cyan {{ background: rgba(56,189,248,0.16); color: #38bdf8; }}
  .pill-emerald {{ background: rgba(52,211,153,0.16); color: #34d399; }}
  .pill-amber {{ background: rgba(251,191,36,0.16); color: #fbbf24; }}
  .alert-box {{
    margin: 10px 14px;
    padding: 9px 12px;
    border-radius: 7px;
    background: rgba(244,63,94,0.14);
    border: 1px solid rgba(244,63,94,0.45);
    color: #fecdd3;
    font-size: 12px;
  }}
  @media (max-width: 980px) {{
    main {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="beam-mark mono">XR</div>
    <div>
      <h1>agent-xray</h1>
      <p>5-bucket context token flamegraph, MCP schema bloat &amp; outbound header firewall</p>
    </div>
  </div>
  <div class="kpis" id="kpi-strip"></div>
</header>

<main>
  <section class="surface">
    <div class="surface-head">
      <h2>Turn-by-turn context token flamegraph</h2>
      <span class="mono" style="font-size:11px;color:var(--muted)" id="turn-subtitle"></span>
    </div>
    <div class="legend">
      <span><i class="swatch" style="background:var(--c-sys)"></i>System prompt</span>
      <span><i class="swatch" style="background:var(--c-rules)"></i>Workspace rules (AGENTS.md / CLAUDE.md)</span>
      <span><i class="swatch" style="background:var(--c-mcp)"></i>MCP &amp; tool schemas</span>
      <span><i class="swatch" style="background:var(--c-results)"></i>Tool outputs &amp; file reads</span>
      <span><i class="swatch" style="background:var(--c-conv)"></i>Conversation</span>
    </div>
    <div class="flame-rows" id="flame-rows"></div>
  </section>

  <div class="right-stack">
    <section class="surface">
      <div class="surface-head">
        <h2>MCP &amp; tool schema token leaderboard</h2>
        <span class="mono" style="font-size:11px;color:var(--c-mcp)" id="mcp-share-badge"></span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Namespace</th>
            <th class="num">Tools</th>
            <th class="num">Tokens / turn</th>
            <th class="num">Share</th>
          </tr>
        </thead>
        <tbody id="ns-tbody"></tbody>
      </table>
    </section>

    <section class="surface">
      <div class="surface-head">
        <h2>Selected turn outbound header &amp; secret egress audit</h2>
        <span class="mono" style="font-size:11px;color:var(--muted)" id="selected-turn-badge"></span>
      </div>
      <div id="secret-banner"></div>
      <table>
        <thead>
          <tr>
            <th>Header</th>
            <th>Observed / transformed value</th>
            <th class="num">Firewall action</th>
          </tr>
        </thead>
        <tbody id="hdr-tbody"></tbody>
      </table>
    </section>
  </div>
</main>

<script>
let DATA = {payload_json};
let selectedIdx = Math.max(0, (DATA.traces || []).length - 2);

function fmt(n) {{
  return Number(n || 0).toLocaleString("en-US");
}}

function render() {{
  const s = DATA.summary || {{}};
  const traces = DATA.traces || [];
  if (selectedIdx >= traces.length) selectedIdx = Math.max(0, traces.length - 1);

  const bt = s.bucket_totals || {{}};
  const mcpPct = s.total_estimated_input > 0
    ? Math.round((bt.mcp_and_tools / s.total_estimated_input) * 100)
    : 0;

  document.getElementById("kpi-strip").innerHTML = `
    <div class="kpi"><div class="val mono">${{fmt(s.total_estimated_input)}}</div><div class="lbl">Estimated prompt tokens</div></div>
    <div class="kpi"><div class="val mono" style="color:var(--c-mcp)">${{mcpPct}}%</div><div class="lbl">MCP schema share</div></div>
    <div class="kpi"><div class="val mono" style="color:var(--c-results)">${{fmt(s.total_cache_read)}}</div><div class="lbl">Prompt cache hits</div></div>
    <div class="kpi"><div class="val mono" style="color:var(--c-sys)">${{fmt(s.stripped_header_count)}}</div><div class="lbl">Telemetry headers stripped</div></div>
    <div class="kpi"><div class="val mono" style="color:${{s.blocked_count ? 'var(--c-mcp)' : 'var(--muted)'}}">${{s.blocked_count || 0}}</div><div class="lbl">Blocked secret leaks</div></div>
  `;

  document.getElementById("turn-subtitle").textContent = `${{traces.length}} captured turns`;

  const maxTurnToks = Math.max(1, ...traces.map(t => (t.buckets && t.buckets.total_estimated) || 1));
  const rowsEl = document.getElementById("flame-rows");
  if (!traces.length) {{
    rowsEl.innerHTML = `<div style="padding:28px;color:var(--muted)">Waiting for coding agent traffic on loopback proxy...</div>`;
  }} else {{
    rowsEl.innerHTML = traces.map((t, idx) => {{
      const b = t.buckets || {{}};
      const tot = Math.max(1, b.total_estimated || 1);
      const scale = (tot / maxTurnToks) * 100;
      const segs = [
        ["var(--c-sys)", b.system_prompt || 0],
        ["var(--c-rules)", b.workspace_rules || 0],
        ["var(--c-mcp)", b.mcp_and_tools || 0],
        ["var(--c-results)", b.tool_results || 0],
        ["var(--c-conv)", b.conversation || 0],
      ];
      const barHtml = segs
        .filter(([, v]) => v > 0)
        .map(([col, v]) => `<div class="seg" style="background:${{col}};width:${{((v / tot) * scale).toFixed(2)}}%"></div>`)
        .join("");
      const statusTag = t.blocked
        ? `<span class="pill pill-rose">Blocked 400</span>`
        : `<span class="mono" style="color:var(--muted)">${{t.latency_ms}} ms</span>`;
      const cls = ["turn-row", idx === selectedIdx ? "active" : "", t.blocked ? "blocked" : ""].join(" ");
      return `
        <div class="${{cls}}" onclick="selectTurn(${{idx}})">
          <div class="turn-meta">
            <div class="turn-title"><strong>Turn ${{t.turn_number}}</strong> &nbsp;${{escapeHtml(t.prompt_preview || t.path)}}</div>
            <div class="turn-toks mono">${{fmt(b.total_estimated)}} tok &nbsp;${{statusTag}}</div>
          </div>
          <div class="bar-track">${{barHtml}}</div>
        </div>
      `;
    }}).join("");
  }}

  const cur = traces[selectedIdx];
  const curNamespaces = cur ? (cur.tool_namespaces || []) : [];
  const nsTotal = Math.max(1, curNamespaces.reduce((a, x) => a + (x.estimated_tokens || 0), 0));
  document.getElementById("mcp-share-badge").textContent = cur
    ? `Turn ${{cur.turn_number}}: ${{fmt(cur.buckets.mcp_and_tools)}} tok`
    : "";
  document.getElementById("ns-tbody").innerHTML = curNamespaces.map(ns => {{
    const pct = Math.round(((ns.estimated_tokens || 0) / nsTotal) * 100);
    const pillCls = ns.namespace.startsWith("mcp:") ? "pill-rose" : "pill-cyan";
    return `
      <tr>
        <td><span class="pill ${{pillCls}} mono">${{escapeHtml(ns.namespace)}}</span></td>
        <td class="num mono">${{ns.tool_count}}</td>
        <td class="num mono">${{fmt(ns.estimated_tokens)}}</td>
        <td class="num mono">${{pct}}%</td>
      </tr>
    `;
  }}).join("") || `<tr><td colspan="4" style="color:var(--muted)">No tool schemas attached on this turn.</td></tr>`;

  document.getElementById("selected-turn-badge").textContent = cur
    ? `Turn ${{cur.turn_number}} (${{cur.model}})`
    : "";

  const secBox = document.getElementById("secret-banner");
  if (cur && cur.secret_findings && cur.secret_findings.length) {{
    secBox.innerHTML = `<div class="alert-box"><strong>Secret egress intercepted:</strong> ` +
      cur.secret_findings.map(f => `${{escapeHtml(f.rule)}} (<span class="mono">${{escapeHtml(f.redacted_snippet)}}</span>)`).join(", ") +
      ` — upstream transmission aborted locally.</div>`;
  }} else {{
    secBox.innerHTML = "";
  }}

  const hdrs = cur ? (cur.header_audit || []) : [];
  document.getElementById("hdr-tbody").innerHTML = hdrs.map(h => {{
    let pill = "pill-cyan";
    if (h.action === "stripped" || h.action === "normalized") pill = "pill-emerald";
    if (h.action === "redacted") pill = "pill-amber";
    return `
      <tr>
        <td class="mono">${{escapeHtml(h.name)}}</td>
        <td class="mono" style="color:var(--muted);font-size:11px">${{escapeHtml(h.display_value)}}</td>
        <td class="num"><span class="pill ${{pill}}">${{escapeHtml(h.action)}}</span></td>
      </tr>
    `;
  }}).join("");
}}

function selectTurn(idx) {{
  selectedIdx = idx;
  render();
}}

function escapeHtml(s) {{
  return String(s || "").replace(/[&<>"']/g, c => ({{
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }}[c]));
}}

render();

if ({poll_js}) {{
  setInterval(async () => {{
    try {{
      const res = await fetch("/_xray/api/summary");
      if (res.ok) {{
        DATA = await res.json();
        render();
      }}
    }} catch (_) {{}}
  }}, 2000);
}}
</script>
</body>
</html>
"""
