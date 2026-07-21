from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .lifecycle import diff_findings


def write_outputs(
    output_dir: Path,
    inventory: dict[str, Any],
    findings: list[dict[str, Any]],
    ruleset: dict[str, Any],
    formats: list[str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    inventory.setdefault("collection", {})["output_dir"] = str(output_dir)
    previous_history = _load_trend_history(output_dir)
    previous_findings = _load_json(output_dir / "findings.json", [])
    previous_changes = _load_json(output_dir / "changes.json", {})
    previous_ruleset = _load_json(output_dir / "ruleset.json", {})
    current_fingerprints = {finding.get("fingerprint") for finding in findings}
    previous_fingerprints = {finding.get("fingerprint") for finding in previous_findings}
    previous_findings.extend(
        finding
        for finding in previous_changes.get("resolved_findings", [])
        if finding.get("fingerprint") in current_fingerprints and finding.get("fingerprint") not in previous_fingerprints
    )
    coverage = inventory.get("collection", {}).get("coverage", {})
    comparison = diff_findings(
        previous_findings,
        findings,
        account_id=inventory.get("account", {}).get("account_id"),
        collection_complete=bool(coverage.get("complete", not inventory.get("collection", {}).get("warnings", []))),
        previous_ruleset_id=previous_ruleset.get("id"),
        current_ruleset_id=ruleset.get("id"),
    )
    findings = comparison["current_findings"]
    summary = build_summary(inventory, findings, ruleset, previous_history, comparison)
    _write_json(output_dir / "inventory.json", inventory)
    _write_json(output_dir / "findings.json", findings)
    _write_json(output_dir / "ruleset.json", ruleset)
    _write_json(output_dir / "summary.json", summary)
    _write_json(output_dir / "changes.json", comparison)
    _write_json(output_dir / "graph.json", inventory.get("attack_graph", {}))
    _write_json(output_dir / "history.json", _update_history(previous_history, summary))
    _write_json(evidence_dir / "collection-warnings.json", inventory.get("collection", {}).get("warnings", []))
    if "csv" in formats:
        (output_dir / "findings.csv").write_text(render_findings_csv(findings), encoding="utf-8")
    if "sarif" in formats:
        _write_json(output_dir / "findings.sarif", render_findings_sarif(findings, summary, inventory))
    if "html" in formats:
        (output_dir / "report.html").write_text(render_html(inventory, findings, ruleset, summary), encoding="utf-8")


def build_summary(
    inventory: dict[str, Any],
    findings: list[dict[str, Any]],
    ruleset: dict[str, Any],
    history: list[dict[str, Any]] | None = None,
    changes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    account = inventory.get("account", {})
    generated = inventory.get("collection", {}).get("generated_at") or datetime.now(timezone.utc).isoformat()
    counts = Counter(finding["severity"] for finding in findings)
    category_counts = Counter(finding["category"] for finding in findings)
    top_principals = Counter(finding["principal"] for finding in findings).most_common(8)
    critical_high = counts["critical"] + counts["high"]
    score = max(0, 100 - (counts["critical"] * 18 + counts["high"] * 10 + counts["medium"] * 4 + counts["low"]))
    rule_sources = _rule_sources(ruleset)
    warnings = inventory.get("collection", {}).get("warnings", [])
    trends = list(history or _load_trend_history(Path(inventory.get("collection", {}).get("output_dir", ""))))
    current_entry = {
        "generated_at": generated,
        "score": score,
        "critical_high": critical_high,
        "total_findings": sum(counts.values()),
    }
    trend_history = trends + [current_entry]
    changes = changes or {
        "counts": dict(Counter(finding.get("lifecycle", "open") for finding in findings)),
        "changes": [],
        "resolved_findings": [],
        "collection_complete": True,
    }
    return {
        "generated_at": generated,
        "account": account,
        "severity_counts": dict(counts),
        "category_counts": dict(category_counts),
        "top_principals": [{"name": name, "count": count} for name, count in top_principals],
        "critical_high": critical_high,
        "score": score,
        "rule_sources": rule_sources,
        "warning_count": len(warnings),
        "warnings": warnings,
        "top_findings": findings[:10],
        "trend_history": trend_history,
        "attack_path_distribution": _attack_path_distribution(findings),
        "coverage": _coverage_metrics(inventory, findings, ruleset),
        "comparison": _compare_to_previous(trends, summary_score=score, summary_critical=critical_high, summary_total=sum(counts.values())),
        "graph_statistics": inventory.get("graph_statistics", {}),
        "change_counts": changes.get("counts", {}),
        "changes": changes.get("changes", []),
        "resolved_findings": changes.get("resolved_findings", []),
        "collection_complete": changes.get("collection_complete", True),
    }


def render_html(
    inventory: dict[str, Any],
    findings: list[dict[str, Any]],
    ruleset: dict[str, Any],
    summary: dict[str, Any] | None = None,
) -> str:
    summary = summary or build_summary(inventory, findings, ruleset)
    account = summary["account"]
    generated = summary["generated_at"]
    rule_sources = summary["rule_sources"]
    cards = (
        "\n".join(_finding_card(finding) for finding in findings)
        or "<p class='empty-state'>No findings at or above the selected threshold.</p>"
    )
    top_fix = (
        "\n".join(
            f"<li><strong>{esc(f['severity'].upper())}</strong> {esc(f['title'])} on <code>{esc(f['principal'])}</code></li>"
            for f in summary["top_findings"]
        )
        or "<li>No findings at or above the selected threshold.</li>"
    )
    principal_items = (
        "\n".join(f"<li><code>{esc(item['name'])}</code><span>{item['count']} findings</span></li>" for item in summary["top_principals"])
        or "<li>No risky principals identified.</li>"
    )
    warning_items = (
        "\n".join(f"<li>{esc(warning)}</li>" for warning in summary["warnings"]) or "<li>No collection limitations recorded.</li>"
    )
    severity_chart = render_severity_chart(summary["severity_counts"])
    principal_chart = render_horizontal_bar_chart(summary["top_principals"], label="findings", color="#175cd3")
    trend_chart = render_trend_chart(summary["trend_history"])
    attack_chart = render_pie_chart(summary["attack_path_distribution"], palette=["#175cd3", "#067647", "#b54708", "#b42318", "#667085"])
    coverage_chart = render_coverage_chart(summary["coverage"])
    comparison_panel = render_change_panel(summary)
    graph_stats = summary.get("graph_statistics", {})
    assessment_brief = render_assessment_brief(summary)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS IAM Exposure Review</title>
  <style>{CSS}</style>
</head>
<body>
  <main>
    <header class="report-header">
      <div class="title-block">
        <p class="eyebrow">AWS IAM Exposure Review</p>
        <h1>{esc(account.get("alias") or account.get("account_id") or "AWS account")}</h1>
        <p class="lede">Who can gain more access, how they get there, and what changed since the previous assessment.</p>
      </div>
      <div class="view-switch" aria-label="Report detail level">
        <button type="button" class="active" data-mode="executive">Executive</button>
        <button type="button" data-mode="practitioner">Practitioner</button>
      </div>
      <div class="meta">
        <span>Account <code>{esc(account.get("account_id") or "unknown")}</code></span>
        <span>Generated {esc(generated)}</span>
        <span>Caller <code>{esc(account.get("caller_arn") or "unknown")}</code></span>
      </div>
    </header>

    <section class="metrics">
      <div><strong>{summary["change_counts"].get("new", 0)}</strong><span>New paths</span></div>
      <div><strong>{summary["change_counts"].get("worsened", 0)}</strong><span>Worsened</span></div>
      <div><strong>{summary["change_counts"].get("resolved", 0)}</strong><span>Resolved</span></div>
      <div><strong>{summary["critical_high"]}</strong><span>Critical/high open</span></div>
      <div><strong>{summary["score"]}</strong><span>Assurance score</span></div>
    </section>

    <section class="change-band">
      <div class="section-heading">
        <div><p class="section-kicker">Since the last complete scan</p><h2>What Changed</h2></div>
        <span class="coverage-state {"complete" if summary["collection_complete"] else "degraded"}">{"Complete comparison" if summary["collection_complete"] else "Resolution held: collection degraded"}</span>
      </div>
      {comparison_panel}
    </section>

    <section class="assessment-brief">
      <h2>Assessment Brief</h2>
      {assessment_brief}
    </section>

    <section class="grid">
      <div>
        <h2>Risk Reduction Priorities</h2>
        <ol class="fixes">{top_fix}</ol>
      </div>
      <div>
        <h2>Top Risky Principals</h2>
        <ul class="split-list">{principal_items}</ul>
      </div>
    </section>

    <section class="grid charts">
      <div>
        <h2>Severity Breakdown</h2>
        {severity_chart}
      </div>
      <div>
        <h2>Top Risky Principals</h2>
        {principal_chart}
      </div>
    </section>

    <section class="grid charts">
      <div>
        <h2>Risk Trend</h2>
        {trend_chart}
      </div>
      <div>
        <h2>Attack Path Distribution</h2>
        {attack_chart}
      </div>
      <div>
        <h2>Collection Coverage</h2>
        {coverage_chart}
      </div>
    </section>

    <section class="practitioner-only">
      <h2>Attack Graph</h2>
      <div class="graph-metrics">
        <div><strong>{graph_stats.get("nodes", 0)}</strong><span>Nodes</span></div>
        <div><strong>{graph_stats.get("edges", 0)}</strong><span>Edges</span></div>
        <div><strong>{graph_stats.get("principal_nodes", 0)}</strong><span>Principals</span></div>
        <div><strong>{graph_stats.get("policy_nodes", 0)}</strong><span>Policies</span></div>
        <div><strong>{graph_stats.get("grant_nodes", 0)}</strong><span>Grants</span></div>
        <div><strong>{graph_stats.get("action_nodes", 0)}</strong><span>Actions</span></div>
        <div><strong>{graph_stats.get("attack_path_nodes", len(findings))}</strong><span>Paths</span></div>
        <div><strong>{graph_stats.get("capability_nodes", 0)}</strong><span>Capabilities</span></div>
      </div>
    </section>

    <section class="practitioner-only rules-coverage">
      <h2>Rules Coverage</h2>
      <p>{esc(ruleset.get("description", "Bundled offline ruleset"))}</p>
      <p><strong>{len(ruleset.get("rules", []))} rules.</strong> Sources: {esc(", ".join(rule_sources))}</p>
    </section>

    <section class="practitioner-only path-inbox" id="attack-paths">
      <div class="section-heading">
        <div><p class="section-kicker">Evidence and remediation</p><h2>Attack Path Inbox</h2></div>
        <span id="visible-count">{len(findings)} paths</span>
      </div>
      <div class="filters" aria-label="Attack path filters">
        <label>Search<input id="path-search" type="search" placeholder="Principal, permission, path or rule"></label>
        <label>Severity<select id="severity-filter"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label>Confidence<select id="status-filter"><option value="all">All</option><option value="confirmed">Confirmed</option><option value="likely">Likely</option><option value="potential">Potential</option></select></label>
        <label>Change<select id="lifecycle-filter"><option value="all">All</option><option value="new">New</option><option value="worsened">Worsened</option><option value="open">Open</option><option value="improved">Improved</option></select></label>
      </div>
      <div class="path-list">{cards}</div>
    </section>

    <section class="practitioner-only">
      <h2>Collection Limitations</h2>
      <ul>{warning_items}</ul>
    </section>
  </main>
  <script>{SCRIPT}</script>
</body>
</html>
"""


def _finding_card(finding: dict[str, Any]) -> str:
    severity = finding["severity"]
    lifecycle = finding.get("lifecycle", "open")
    status = finding.get("status", "confirmed")
    search = " ".join(
        str(finding.get(field, "")) for field in ("id", "title", "principal", "principal_type", "category", "attack_path")
    ).lower()
    sources = " · ".join(finding.get("source", [])) or "Project rule"
    evidence = json.dumps(finding.get("evidence", []), indent=2, sort_keys=True, default=str)
    fingerprint = finding.get("fingerprint", "")[:12]
    return f"""
<article class="path-card sev-{esc(severity)}" data-severity="{esc(severity)}" data-status="{esc(status)}" data-lifecycle="{esc(lifecycle)}" data-search="{esc(search)}">
  <div class="path-card-head">
    <div class="badges"><span class="badge">{esc(severity.upper())}</span><span class="state-badge">{esc(status.title())}</span><span class="change-badge">{esc(lifecycle.title())}</span></div>
    <code>#{esc(fingerprint)}</code>
  </div>
  <h3>{esc(finding.get("title", ""))}</h3>
  <p class="impact">{esc(finding.get("business_impact", ""))}</p>
  <div class="path-line"><span>Starting principal</span><code>{esc(finding.get("principal_type", "unknown"))}:{esc(finding.get("principal", "unknown"))}</code></div>
  <div class="path-line"><span>Observed path</span><code>{esc(finding.get("attack_path", ""))}</code></div>
  <div class="remediation"><strong>Reduce the path</strong><p>{esc(finding.get("recommended_action", ""))}</p></div>
  <details>
    <summary>Technical evidence and attribution</summary>
    <p><strong>Rule:</strong> <code>{esc(finding.get("id", ""))}</code></p>
    <p><strong>Research:</strong> {esc(sources)}</p>
    <pre>{esc(evidence)}</pre>
  </details>
</article>
"""


def _rule_sources(ruleset: dict[str, Any]) -> list[str]:
    sources = set()
    for rule in ruleset.get("rules", []):
        sources.update(rule.get("source", []))
    return sorted(sources)


def _attack_path_distribution(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(finding.get("category", "other") for finding in findings)
    return dict(counts)


def _coverage_metrics(inventory: dict[str, Any], findings: list[dict[str, Any]], ruleset: dict[str, Any]) -> dict[str, Any]:
    warnings = inventory.get("collection", {}).get("warnings", [])
    return {
        "users": len(inventory.get("users", [])),
        "groups": len(inventory.get("groups", [])),
        "roles": len(inventory.get("roles", [])),
        "warnings": len(warnings),
        "rules": len(ruleset.get("rules", [])),
        "findings": len(findings),
    }


def _update_history(history: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    history = list(history)
    history.append(
        {
            "generated_at": summary["generated_at"],
            "score": summary["score"],
            "critical_high": summary["critical_high"],
            "total_findings": sum(summary["severity_counts"].values()),
        }
    )
    return history[-20:]


def _load_trend_history(output_dir: Path) -> list[dict[str, Any]]:
    if not output_dir or str(output_dir) == ".":
        return []
    history_path = output_dir / "history.json"
    if not history_path.exists():
        return []
    try:
        return json.loads(history_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _compare_to_previous(history: list[dict[str, Any]], summary_score: int, summary_critical: int, summary_total: int) -> dict[str, Any]:
    previous = history[-1] if history else {}
    return {
        "has_previous": bool(previous),
        "previous_score": previous.get("score"),
        "score_delta": None if previous.get("score") is None else summary_score - previous.get("score", 0),
        "critical_delta": None if previous.get("critical_high") is None else summary_critical - previous.get("critical_high", 0),
        "findings_delta": None if previous.get("total_findings") is None else summary_total - previous.get("total_findings", 0),
    }


def render_severity_chart(severity_counts: dict[str, int]) -> str:
    order = [("critical", "#b42318"), ("high", "#b54708"), ("medium", "#175cd3"), ("low", "#067647"), ("info", "#667085")]
    total = max(1, sum(severity_counts.values()))
    parts = []
    for name, color in order:
        count = severity_counts.get(name, 0)
        if not count:
            continue
        parts.append(f"<span style='width:{(count / total) * 100:.2f}%;background:{color}' title='{esc(name)}: {count}'></span>")
    legend = "".join(
        f"<li><span class='legend-swatch' style='background:{color}'></span>{esc(name.title())} <strong>{severity_counts.get(name, 0)}</strong></li>"
        for name, color in order
        if severity_counts.get(name, 0)
    )
    return f"<div class='stacked-bar'>{''.join(parts)}</div><ul class='legend'>{legend}</ul>"


def render_horizontal_bar_chart(items: list[dict[str, Any]], label: str, color: str) -> str:
    max_value = max((item["count"] for item in items), default=1)
    bars = []
    for item in items:
        width = (item["count"] / max_value) * 100
        bars.append(
            f"<li><span>{esc(item['name'])}</span><div class='bar-wrap'><i style='width:{width:.2f}%;background:{color}'></i><em>{item['count']} {esc(label)}</em></div></li>"
        )
    return f"<ul class='chart-list'>{''.join(bars) or '<li>No data</li>'}</ul>"


def render_category_chart(category_counts: dict[str, int]) -> str:
    total = max(1, sum(category_counts.values()))
    return _pie_or_donut_chart(category_counts, total)


def render_pie_chart(category_counts: dict[str, int], palette: list[str]) -> str:
    return _pie_or_donut_chart(category_counts, max(1, sum(category_counts.values())), palette)


def _pie_or_donut_chart(items: dict[str, int], total: int, palette: list[str] | None = None) -> str:
    palette = palette or ["#175cd3", "#067647", "#b54708", "#b42318", "#667085"]
    if not items:
        return "<p class='empty-chart'>No data.</p>"
    segments = []
    legend = []
    start = 0.0
    colors = palette * ((len(items) // len(palette)) + 1)
    for (name, count), color in zip(sorted(items.items(), key=lambda item: item[1], reverse=True), colors, strict=False):
        pct = count / total
        angle = pct * 360
        segments.append(f"{color} {start:.2f}deg {start + angle:.2f}deg")
        legend.append(
            f"<li><span class='legend-swatch' style='background:{color}'></span>{esc(name.replace('-', ' ').title())} <strong>{count}</strong></li>"
        )
        start += angle
    return (
        f"<div class='pie-chart' style='background: conic-gradient({', '.join(segments)})'></div><ul class='legend'>{''.join(legend)}</ul>"
    )


def render_trend_chart(history: list[dict[str, Any]]) -> str:
    if not history:
        return "<p class='empty-chart'>Run the scanner again in the same output folder to build a trend line.</p>"
    max_score = max((item.get("score", 0) for item in history), default=100)
    min_score = min((item.get("score", 0) for item in history), default=0)
    span = max(1, max_score - min_score)
    points = []
    width = 620
    height = 220
    for index, item in enumerate(history):
        x = 30 + (index * (width - 60) / max(1, len(history) - 1))
        y = 25 + (1 - (item.get("score", 0) - min_score) / span) * (height - 50)
        points.append((x, y, item.get("score", 0), item.get("generated_at", "")))
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y, *_ in points)
    dots = "".join(
        f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4' fill='#175cd3'><title>{esc(label)}: score {score}</title></circle>"
        for x, y, score, label in points
    )
    grid = "".join(f"<line x1='30' y1='{y}' x2='590' y2='{y}' stroke='#e4e7ec' />" for y in (25, 75, 125, 175))
    return f"""
<svg viewBox="0 0 {width} {height}" class="trend-svg" role="img" aria-label="Risk trend line">
  {grid}
  <polyline points="{line}" fill="none" stroke="#175cd3" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></polyline>
  {dots}
</svg>
"""


def render_coverage_chart(coverage: dict[str, Any]) -> str:
    items = [
        ("Users", coverage.get("users", 0), "#175cd3"),
        ("Roles", coverage.get("roles", 0), "#067647"),
        ("Groups", coverage.get("groups", 0), "#b54708"),
        ("Warnings", coverage.get("warnings", 0), "#b42318"),
    ]
    max_value = max(1, max((count for _, count, _ in items), default=0))
    bars = "".join(
        f"<li><span>{name}</span><div class='bar-wrap'><i style='width:{(count / max_value) * 100:.2f}%;background:{color}'></i><em>{count}</em></div></li>"
        for name, count, color in items
    )
    return f"<ul class='chart-list'>{bars}</ul>"


def render_change_panel(summary: dict[str, Any]) -> str:
    changes = summary.get("changes", [])
    if not changes:
        return "<div class='quiet-state'><strong>No material path changes.</strong><span>Open paths are unchanged from the previous complete assessment.</span></div>"
    items = []
    for change in changes[:8]:
        finding = change.get("finding", {})
        lifecycle = change.get("lifecycle", "open")
        items.append(
            f"<li class='change-{esc(lifecycle)}'>"
            f"<span class='change-badge'>{esc(lifecycle.title())}</span>"
            f"<div><strong>{esc(finding.get('title', 'Attack path'))}</strong>"
            f"<small><code>{esc(finding.get('principal', 'unknown'))}</code> · {esc(finding.get('severity', 'info').upper())} · {esc(change.get('reason', 'environment_change').replace('_', ' '))}</small></div>"
            "</li>"
        )
    remaining = len(changes) - len(items)
    suffix = f"<p class='change-more'>{remaining} additional changes are included in <code>changes.json</code>.</p>" if remaining else ""
    return f"<ol class='change-list'>{''.join(items)}</ol>{suffix}"


def render_comparison_panel(comparison: dict[str, Any], history: list[dict[str, Any]]) -> str:
    if not comparison.get("has_previous"):
        return "<p class='empty-chart'>This is the first scan in this output folder. Run another scan here to compare results and show risk reduction over time.</p>"

    def fmt(value: Any) -> str:
        if value is None:
            return "n/a"
        if isinstance(value, (int, float)) and value > 0:
            return f"+{value}"
        return str(value)

    items = [
        ("Assurance score", fmt(comparison.get("score_delta")), "#067647"),
        ("Critical/high", fmt(comparison.get("critical_delta")), "#b42318"),
        ("Total findings", fmt(comparison.get("findings_delta")), "#175cd3"),
    ]
    latest = history[-2:] if len(history) >= 2 else history
    labels = ["Previous", "Current"][-len(latest) :]
    timeline = (
        "".join(
            f"<li><strong>{label}</strong><span>{esc(item.get('generated_at', ''))}<br>score {item.get('score', 0)} · critical/high {item.get('critical_high', 0)}</span></li>"
            for label, item in zip(labels, latest, strict=False)
        )
        or "<li>No prior scans.</li>"
    )
    rows = "".join(f"<li><span>{label}</span><strong style='color:{color}'>{delta}</strong></li>" for label, delta, color in items)
    return f"<div class='comparison-grid'><ul class='split-list'>{rows}</ul><ul class='split-list'>{timeline}</ul></div>"


def render_assessment_brief(summary: dict[str, Any]) -> str:
    top = summary.get("top_findings", [])
    first = top[0] if top else {}
    finding_text = first.get("title", "No high-priority IAM attack paths identified")
    principal = first.get("principal", "n/a")
    attack_path = first.get("attack_path", "No attack path evidence at the selected threshold.")
    action = first.get("recommended_action", "Keep scan history and review collection warnings before sharing assurance.")
    score = summary.get("score", 0)
    critical_high = summary.get("critical_high", 0)
    warning_count = summary.get("warning_count", 0)
    return f"""
<div class="brief-grid">
  <div>
    <span class="brief-label">Fix first</span>
    <strong>{esc(finding_text)}</strong>
    <small>Principal: <code>{esc(principal)}</code></small>
  </div>
  <div>
    <span class="brief-label">Proof</span>
    <code>{esc(attack_path)}</code>
  </div>
  <div>
    <span class="brief-label">Action</span>
    <p>{esc(action)}</p>
  </div>
  <div>
    <span class="brief-label">Assurance</span>
    <strong>{score}/100</strong>
    <small>{critical_high} critical/high findings · {warning_count} collection warnings</small>
  </div>
</div>
"""


def render_findings_csv(findings: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "fingerprint",
            "lifecycle",
            "severity",
            "status",
            "principal",
            "principal_type",
            "title",
            "category",
            "attack_path",
            "recommended_action",
        ]
    )
    for finding in findings:
        writer.writerow(
            [
                finding.get("fingerprint", ""),
                finding.get("lifecycle", ""),
                finding.get("severity", ""),
                finding.get("status", ""),
                finding.get("principal", ""),
                finding.get("principal_type", ""),
                finding.get("title", ""),
                finding.get("category", ""),
                finding.get("attack_path", ""),
                finding.get("recommended_action", ""),
            ]
        )
    return buffer.getvalue()


def render_findings_sarif(findings: list[dict[str, Any]], summary: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    rules = []
    seen_rule_ids = set()
    for finding in findings:
        rule_id = finding.get("id")
        if rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": finding.get("title"),
                "shortDescription": {"text": finding.get("title", "")},
                "fullDescription": {"text": finding.get("business_impact", "")},
                "help": {"text": finding.get("recommended_action", "")},
            }
        )
    runs = [
        {
            "tool": {
                "driver": {
                    "name": "AWS IAM Exposure Review",
                    "informationUri": "https://example.com/aws-iam-exposure-review",
                    "rules": rules,
                }
            },
            "results": [
                {
                    "ruleId": finding.get("id"),
                    "level": _sarif_level(finding.get("severity", "info")),
                    "message": {"text": finding.get("attack_path", finding.get("title", ""))},
                    "properties": {
                        "principal": finding.get("principal"),
                        "principalType": finding.get("principal_type"),
                        "status": finding.get("status"),
                        "confidence": finding.get("confidence"),
                        "source": finding.get("source"),
                        "category": finding.get("category"),
                        "fingerprint": finding.get("fingerprint"),
                        "lifecycle": finding.get("lifecycle"),
                    },
                }
                for finding in findings
            ],
            "invocations": [
                {
                    "executionSuccessful": True,
                    "properties": {
                        "accountId": inventory.get("account", {}).get("account_id"),
                        "summaryScore": summary.get("score"),
                        "criticalHigh": summary.get("critical_high"),
                    },
                }
            ],
        }
    ]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "note")


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


CSS = """
:root {
  color-scheme: light;
  --ink: #182026;
  --muted: #52616b;
  --line: #d9e1e7;
  --bg: #f7f9fb;
  --panel: #ffffff;
  --red: #b42318;
  --amber: #b54708;
  --green: #067647;
  --blue: #175cd3;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: Aptos, "Avenir Next", "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }
main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 56px; }
.report-header { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: start; border-bottom: 1px solid var(--line); padding: 28px 0 24px; }
.title-block { min-width: 0; }
.report-header .meta { grid-column: 1 / -1; }
.eyebrow { color: var(--blue); font-weight: 700; letter-spacing: 0; text-transform: uppercase; font-size: 13px; margin: 0 0 8px; }
h1 { font-size: 42px; line-height: 1.08; margin: 0; }
h2 { font-size: 20px; margin: 0 0 14px; }
.lede { max-width: 760px; color: var(--muted); font-size: 18px; line-height: 1.5; }
.meta { display: flex; flex-wrap: wrap; gap: 10px; color: var(--muted); font-size: 13px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: normal; word-break: break-word; }
.metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 22px 0; }
.metrics div, section.grid > div, .assessment-brief, .change-band, .rules-coverage, main > section.practitioner-only:not(.path-inbox) { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; }
.metrics strong { display: block; font-size: 32px; line-height: 1; }
.metrics span, small, .split-list span { color: var(--muted); }
.brief-grid { display:grid; grid-template-columns: 1.1fr 1.4fr 1.2fr .8fr; gap: 14px; }
.brief-grid div { border-left: 4px solid var(--blue); padding-left: 12px; min-width: 0; }
.brief-grid strong { display:block; font-size: 18px; line-height: 1.25; margin: 4px 0 8px; }
.brief-grid p { margin: 4px 0 0; line-height: 1.45; }
.brief-label { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 18px 0; }
section { margin: 18px 0; }
.section-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin-bottom:14px; }
.section-heading h2 { margin-bottom:0; }
.section-kicker { margin:0 0 4px; color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }
.view-switch { display:flex; gap:4px; padding:4px; background:#eef2f6; border:1px solid var(--line); border-radius:8px; }
.view-switch button { min-height:36px; border:0; border-radius:6px; padding:0 12px; background:transparent; color:var(--muted); font:inherit; font-weight:700; cursor:pointer; }
.view-switch button.active { background:var(--panel); color:var(--ink); box-shadow:0 1px 2px rgba(16,24,40,.08); }
.coverage-state { border-radius:6px; padding:6px 9px; font-size:12px; font-weight:700; }
.coverage-state.complete { color:var(--green); background:#ecfdf3; }
.coverage-state.degraded { color:var(--amber); background:#fffaeb; }
.change-list { list-style:none; display:grid; gap:0; margin:0; padding:0; }
.change-list li { display:grid; grid-template-columns:90px minmax(0,1fr); align-items:start; gap:12px; padding:11px 0; border-top:1px solid var(--line); }
.change-list li:first-child { border-top:0; }
.change-list strong, .change-list small { display:block; }
.change-list small { margin-top:3px; color:var(--muted); }
.change-badge, .state-badge { display:inline-flex; width:max-content; align-items:center; min-height:24px; border:1px solid var(--line); border-radius:6px; padding:2px 7px; background:#f8fafc; color:var(--muted); font-size:11px; font-weight:700; }
.change-new .change-badge, .path-card[data-lifecycle="new"] .change-badge { color:var(--blue); background:#eff8ff; border-color:#b2ddff; }
.change-worsened .change-badge, .path-card[data-lifecycle="worsened"] .change-badge { color:var(--red); background:#fef3f2; border-color:#fecdca; }
.change-resolved .change-badge { color:var(--green); background:#ecfdf3; border-color:#abefc6; }
.quiet-state { display:flex; justify-content:space-between; gap:18px; color:var(--muted); }
.quiet-state strong { color:var(--green); }
.change-more { margin:12px 0 0; color:var(--muted); }
.fixes { padding-left: 22px; line-height: 1.65; }
.split-list { list-style: none; padding: 0; margin: 0; }
.split-list li { display: flex; justify-content: space-between; gap: 18px; border-top: 1px solid var(--line); padding: 10px 0; }
.split-list li:first-child { border-top: 0; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; vertical-align: top; border-top: 1px solid var(--line); padding: 12px; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; }
.badge { color: white; border-radius: 6px; padding: 4px 7px; font-size: 11px; font-weight: 700; }
.sev-critical .badge { background: var(--red); }
.sev-high .badge { background: var(--amber); }
.sev-medium .badge { background: var(--blue); }
.sev-low .badge, .sev-info .badge { background: var(--green); }
.charts > div { min-height: 320px; }
.graph-metrics { display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.graph-metrics div { background: var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
.graph-metrics strong { display:block; font-size: 28px; }
.comparison-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.comparison-grid .split-list { min-height: 100%; }
.stacked-bar { display: flex; height: 18px; overflow: hidden; border-radius: 8px; border: 1px solid var(--line); background: #eef2f6; }
.stacked-bar span { display: block; height: 100%; }
.legend { list-style: none; margin: 14px 0 0; padding: 0; display: grid; gap: 8px; }
.legend li { display: flex; align-items: center; gap: 8px; color: var(--muted); }
.legend strong { color: var(--ink); margin-left: auto; }
.legend-swatch { width: 12px; height: 12px; border-radius: 3px; display: inline-block; }
.chart-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 12px; }
.chart-list li { display: grid; gap: 6px; }
.chart-list span { color: var(--ink); font-weight: 600; }
.bar-wrap { position: relative; height: 18px; background: #eef2f6; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
.bar-wrap i { display: block; height: 100%; border-radius: 8px; }
.bar-wrap em { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); font-style: normal; font-size: 12px; color: var(--ink); }
.pie-chart { width: 190px; aspect-ratio: 1; border-radius: 50%; margin: 6px auto 12px; position: relative; border: 1px solid var(--line); }
.pie-chart::after { content: ""; position: absolute; inset: 24%; background: var(--panel); border-radius: 50%; border: 1px solid var(--line); }
.trend-svg { width: 100%; height: auto; display: block; }
.empty-chart { color: var(--muted); }
.practitioner-only { display:none; }
body.mode-practitioner .practitioner-only { display:block; }
.path-inbox { padding:8px 0 0; }
.filters { display:grid; grid-template-columns:2fr repeat(3, minmax(130px, 1fr)); gap:12px; align-items:end; margin:0 0 16px; }
.filters label { display:grid; gap:5px; color:var(--muted); font-size:12px; font-weight:700; }
.filters input, .filters select { width:100%; min-height:42px; border:1px solid var(--line); border-radius:6px; background:var(--panel); color:var(--ink); padding:8px 10px; font:inherit; font-weight:400; }
.filters input:focus, .filters select:focus, button:focus-visible, summary:focus-visible { outline:3px solid #b2ddff; outline-offset:2px; }
.path-list { display:grid; gap:12px; }
.path-card { background:var(--panel); border:1px solid var(--line); border-left:5px solid var(--blue); border-radius:8px; padding:18px; min-width:0; }
.path-card.sev-critical { border-left-color:var(--red); }
.path-card.sev-high { border-left-color:var(--amber); }
.path-card.sev-low { border-left-color:var(--green); }
.path-card[hidden] { display:none; }
.path-card-head { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.badges { display:flex; flex-wrap:wrap; gap:6px; }
.path-card h3 { margin:14px 0 6px; font-size:19px; }
.impact { margin:0 0 14px; color:var(--muted); line-height:1.5; }
.path-line { display:grid; grid-template-columns:140px minmax(0,1fr); gap:12px; padding:9px 0; border-top:1px solid var(--line); }
.path-line span { color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }
.remediation { margin:12px 0; padding:12px 14px; border-left:4px solid var(--green); background:#f6fef9; }
.remediation p { margin:5px 0 0; }
details { border-top:1px solid var(--line); padding-top:12px; }
summary { cursor:pointer; color:var(--blue); font-weight:700; }
pre { max-height:360px; overflow:auto; border:1px solid var(--line); border-radius:6px; padding:12px; background:#f8fafc; white-space:pre-wrap; overflow-wrap:anywhere; font-size:12px; }
.empty-state { padding:32px; text-align:center; color:var(--muted); border:1px dashed var(--line); border-radius:8px; }
@media (max-width: 800px) {
  h1 { font-size: 30px; }
  .report-header, .metrics, .grid, .brief-grid, .filters { grid-template-columns: 1fr; }
  .report-header .meta { grid-column:auto; }
  .view-switch { width:max-content; }
  .path-line { grid-template-columns:1fr; gap:4px; }
  .section-heading, .quiet-state { flex-direction:column; }
  .comparison-grid { grid-template-columns: 1fr; }
}
@media print {
  body { background:#fff; }
  main { width:100%; padding:0; }
  .view-switch, .filters { display:none !important; }
  .practitioner-only { display:block !important; }
  .path-card, section { break-inside:avoid; }
}
"""


SCRIPT = """
(() => {
  const body = document.body;
  const modeButtons = Array.from(document.querySelectorAll('[data-mode]'));
  const setMode = (mode) => {
    body.classList.toggle('mode-practitioner', mode === 'practitioner');
    modeButtons.forEach((button) => button.classList.toggle('active', button.dataset.mode === mode));
  };
  modeButtons.forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));

  const search = document.getElementById('path-search');
  const severity = document.getElementById('severity-filter');
  const status = document.getElementById('status-filter');
  const lifecycle = document.getElementById('lifecycle-filter');
  const count = document.getElementById('visible-count');
  const cards = Array.from(document.querySelectorAll('.path-card'));
  const applyFilters = () => {
    const query = (search?.value || '').trim().toLowerCase();
    let visible = 0;
    cards.forEach((card) => {
      const matches = (!query || card.dataset.search.includes(query))
        && (!severity || severity.value === 'all' || card.dataset.severity === severity.value)
        && (!status || status.value === 'all' || card.dataset.status === status.value)
        && (!lifecycle || lifecycle.value === 'all' || card.dataset.lifecycle === lifecycle.value);
      card.hidden = !matches;
      if (matches) visible += 1;
    });
    if (count) count.textContent = `${visible} ${visible === 1 ? 'path' : 'paths'}`;
  };
  [search, severity, status, lifecycle].filter(Boolean).forEach((control) => control.addEventListener('input', applyFilters));
})();
"""
