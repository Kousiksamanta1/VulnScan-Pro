"""Reporting helpers for exporting scan results in multiple formats."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from scanner_storage import build_scan_snapshot, collect_findings

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except ModuleNotFoundError:  # pragma: no cover - optional dependency.
    SimpleDocTemplate = None


def export_json(scan_results: dict[str, Any], output_path: Path) -> Path:
    """Write scan results as formatted JSON."""
    output_path.write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
    return output_path


def export_csv(scan_results: dict[str, Any], output_path: Path) -> Path:
    """Write scan results as a flat CSV report centered on port results."""
    findings = collect_findings(scan_results)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Target", scan_results.get("target", "")])
        writer.writerow(["Status", scan_results.get("status", "")])
        writer.writerow(["Started At", scan_results.get("started_at", "")])
        writer.writerow(["Finished At", scan_results.get("finished_at", "")])
        writer.writerow([])
        writer.writerow(["Port", "Service", "Status", "Severity", "Latency (ms)", "Banner"])
        for port_result in scan_results.get("ports", []):
            writer.writerow(
                [
                    port_result.get("port", ""),
                    port_result.get("service", ""),
                    port_result.get("status", ""),
                    port_result.get("severity", ""),
                    port_result.get("latency_ms", ""),
                    port_result.get("banner", ""),
                ]
            )
        writer.writerow([])
        writer.writerow(["Findings"])
        writer.writerow(["Source", "Severity", "Name", "Evidence"])
        for finding in findings:
            writer.writerow(
                [
                    finding.get("source", ""),
                    finding.get("severity", ""),
                    finding.get("name", ""),
                    finding.get("evidence", ""),
                ]
            )
    return output_path


def export_html(scan_results: dict[str, Any], output_path: Path) -> Path:
    """Write scan results as a styled standalone HTML report."""
    snapshot = build_scan_snapshot(scan_results)
    findings = collect_findings(scan_results)
    rows = "\n".join(
        f"""
        <tr>
            <td>{html.escape(str(port_result.get("port", "")))}</td>
            <td>{html.escape(port_result.get("service", ""))}</td>
            <td>{html.escape(port_result.get("status", ""))}</td>
            <td>{html.escape(port_result.get("severity", ""))}</td>
            <td>{html.escape(str(port_result.get("latency_ms", "")))}</td>
            <td>{html.escape(port_result.get("banner", ""))}</td>
        </tr>
        """
        for port_result in scan_results.get("ports", [])
    )
    finding_rows = "\n".join(
        f"""
        <li>
            <strong>{html.escape(finding.get("severity", "").upper())}</strong>
            {html.escape(finding.get("name", ""))}
            <span>{html.escape(finding.get("evidence", ""))}</span>
        </li>
        """
        for finding in findings
    )
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VulnScan Pro Report</title>
    <style>
        body {{
            margin: 0;
            padding: 40px;
            background: #09111d;
            color: #e2e8f0;
            font-family: "Avenir Next", "Segoe UI", sans-serif;
        }}
        .hero {{
            background: linear-gradient(135deg, #10203b, #0f172a);
            border: 1px solid #1e3a5f;
            border-radius: 24px;
            padding: 28px;
            margin-bottom: 24px;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #101826;
            border: 1px solid #1f2b3f;
            border-radius: 18px;
            padding: 18px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #101826;
            border-radius: 18px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 14px;
            border-bottom: 1px solid #1f2b3f;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #132033;
            color: #93c5fd;
        }}
        ul {{
            background: #101826;
            border: 1px solid #1f2b3f;
            border-radius: 18px;
            padding: 18px 24px;
        }}
        li {{
            margin-bottom: 10px;
        }}
        span {{
            display: block;
            color: #94a3b8;
            margin-top: 4px;
        }}
    </style>
</head>
<body>
    <section class="hero">
        <h1>VulnScan Pro Report</h1>
        <p>Target: {html.escape(scan_results.get("target", ""))}</p>
        <p>Status: {html.escape(scan_results.get("status", ""))}</p>
        <p>Started: {html.escape(scan_results.get("started_at", ""))}</p>
        <p>Finished: {html.escape(scan_results.get("finished_at", ""))}</p>
    </section>
    <section class="cards">
        <div class="card"><strong>Open Ports</strong><div>{snapshot.get("open_ports_count", 0)}</div></div>
        <div class="card"><strong>Findings</strong><div>{snapshot.get("findings_count", 0)}</div></div>
        <div class="card"><strong>Risk</strong><div>{html.escape(snapshot.get("highest_severity", "info").upper())}</div></div>
        <div class="card"><strong>TLS Grade</strong><div>{html.escape(snapshot.get("tls_grade", "Unavailable"))}</div></div>
    </section>
    <h2>Port Inventory</h2>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Latency</th>
                <th>Banner</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <h2>Findings</h2>
    <ul>
        {finding_rows or "<li>No findings recorded.</li>"}
    </ul>
</body>
</html>"""
    output_path.write_text(document, encoding="utf-8")
    return output_path


def export_pdf(scan_results: dict[str, Any], output_path: Path) -> Path:
    """Write scan results as a PDF report using ReportLab."""
    if SimpleDocTemplate is None:
        raise ModuleNotFoundError("reportlab is required for PDF export.")

    snapshot = build_scan_snapshot(scan_results)
    findings = collect_findings(scan_results)
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(output_path), pagesize=A4)
    story = [
        Paragraph("VulnScan Pro Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Target: {scan_results.get('target', '')}", styles["BodyText"]),
        Paragraph(f"Status: {scan_results.get('status', '')}", styles["BodyText"]),
        Paragraph(f"Started: {scan_results.get('started_at', '')}", styles["BodyText"]),
        Paragraph(f"Finished: {scan_results.get('finished_at', '')}", styles["BodyText"]),
        Spacer(1, 16),
        Paragraph(
            (
                f"Open Ports: {snapshot.get('open_ports_count', 0)} | "
                f"Findings: {snapshot.get('findings_count', 0)} | "
                f"Risk: {snapshot.get('highest_severity', 'info').upper()} | "
                f"TLS Grade: {snapshot.get('tls_grade', 'Unavailable')}"
            ),
            styles["Heading2"],
        ),
        Spacer(1, 12),
    ]

    table_data = [["Port", "Service", "Status", "Severity", "Latency", "Banner"]]
    for port_result in scan_results.get("ports", []):
        table_data.append(
            [
                str(port_result.get("port", "")),
                port_result.get("service", ""),
                port_result.get("status", ""),
                port_result.get("severity", ""),
                str(port_result.get("latency_ms", "")),
                port_result.get("banner", "")[:60],
            ]
        )

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Findings", styles["Heading2"]))

    if findings:
        for finding in findings:
            story.append(
                Paragraph(
                    (
                        f"<b>{finding.get('severity', '').upper()}</b> "
                        f"{finding.get('name', '')}: {finding.get('evidence', '')}"
                    ),
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No findings recorded.", styles["BodyText"]))

    document.build(story)
    return output_path


def export_scan_results(scan_results: dict[str, Any], output_path: Path, export_format: str) -> Path:
    """Route an export request to the correct report writer."""
    normalized_format = export_format.strip().upper()
    if normalized_format == "JSON":
        return export_json(scan_results, output_path)
    if normalized_format == "CSV":
        return export_csv(scan_results, output_path)
    if normalized_format == "HTML":
        return export_html(scan_results, output_path)
    if normalized_format == "PDF":
        return export_pdf(scan_results, output_path)
    raise ValueError(f"Unsupported export format '{export_format}'.")
