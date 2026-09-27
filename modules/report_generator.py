"""JSON and Jinja2 HTML report generation."""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

SEVERITIES = ("High", "Medium", "Low", "Info")


def build_report(
    target,
    hostname,
    started_at,
    port_results,
    port_findings,
    http_result,
    ssl_result,
):
    categories = {
        "Port Scanner": port_findings,
        "HTTP Header & Misconfiguration Analyzer": http_result.get("findings", []),
        "SSL/TLS Inspector": ssl_result.get("findings", []),
    }

    all_findings = [
        finding for category in categories.values() for finding in category
    ]
    counts = {severity: 0 for severity in SEVERITIES}
    for item in all_findings:
        severity = item.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1

    return {
        "tool": {
            "name": "Web Security Assessment Toolkit",
            "version": "3.0.0",
        },
        "target": {
            "input": target,
            "hostname": hostname,
        },
        "scan": {
            "timestamp_utc": started_at,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": counts,
        },
        "categories": categories,
        "raw": {
            "ports": port_results,
            "http": http_result,
            "ssl": ssl_result,
        },
    }


def write_report(report: dict, output_path: str, format_name: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if format_name == "json":
        path.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
        return str(path)

    template_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    html = env.get_template("report_template.html").render(report=report)
    path.write_text(html, encoding="utf-8")
    return str(path)
