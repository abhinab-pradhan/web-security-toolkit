#!/usr/bin/env python3
"""Web Security Assessment Toolkit v2 - CLI entry point."""

import argparse
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules.port_scanner import scan_ports
from modules.header_analyzer import analyze_http
from modules.ssl_checker import inspect_ssl
from modules.report_generator import build_report, write_report

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]


def parse_ports(value: str) -> list[int]:
    ports = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port: {item}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {port}")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("At least one port is required")
    return list(dict.fromkeys(ports))


def normalize_target(target: str) -> tuple[str, str]:
    raw = target.strip()
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("Target must be a hostname or URL")
    return parsed.hostname, raw.rstrip("/")


def validate_reachable(hostname: str, timeout: float) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionError(f"DNS resolution failed for {hostname}: {exc}") from exc

    addresses = sorted({info[4][0] for info in infos})
    for port in (443, 80):
        for address in addresses:
            try:
                with socket.create_connection((address, port), timeout=timeout):
                    return addresses
            except OSError:
                continue

    raise ConnectionError(
        f"{hostname} resolved to {', '.join(addresses)}, but ports 80/443 were not reachable."
    )


def print_summary(label: str, findings: list[dict]) -> None:
    high = sum(x.get("severity") == "High" for x in findings)
    medium = sum(x.get("severity") == "Medium" for x in findings)
    low = sum(x.get("severity") == "Low" for x in findings)
    info = sum(x.get("severity") == "Info" for x in findings)
    print(
        f"[+] {label}: {len(findings)} finding(s) | "
        f"High={high} Medium={medium} Low={low} Info={info}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lightweight Web Security Assessment Toolkit"
    )
    parser.add_argument("--target", required=True, help="Hostname or URL")
    parser.add_argument("--output", default="report.html", help="Report file")
    parser.add_argument("--format", choices=("json", "html"), default="html")
    parser.add_argument("--ports", type=parse_ports, default=DEFAULT_PORTS)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    try:
        hostname, base_url = normalize_target(args.target)
        print(f"[*] Target: {hostname}")
        print("[*] Validating reachability...")
        addresses = validate_reachable(hostname, args.timeout)
        print(f"[+] Reachable/resolvable: {', '.join(addresses)}")
    except (ValueError, ConnectionError) as exc:
        print(f"[!] Target validation failed: {exc}", file=sys.stderr)
        return 2

    timestamp = datetime.now(timezone.utc).isoformat()

    print("[*] Running TCP connect port scan...")
    try:
        port_results = scan_ports(hostname, args.ports, timeout=args.timeout)
        port_findings = [
            {
                "title": f"Open TCP port {item['port']}",
                "severity": "Info",
                "description": (
                    f"TCP connect succeeded on port {item['port']}."
                    + (f" Banner: {item['banner']}" if item.get("banner") else "")
                ),
                "remediation": (
                    "Confirm the service is required; restrict administrative services "
                    "to trusted networks where appropriate."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
            }
            for item in port_results
            if item.get("status") == "open"
        ]
        print_summary("Port scanner", port_findings)
    except Exception as exc:
        print(f"[!] Port scanner error: {exc}", file=sys.stderr)
        port_results, port_findings = [], []

    print("[*] Running HTTP/HTTPS analysis...")
    try:
        http_result = analyze_http(hostname, base_url, timeout=args.timeout)
        print_summary("HTTP analyzer", http_result.get("findings", []))
    except Exception as exc:
        print(f"[!] HTTP analyzer error: {exc}", file=sys.stderr)
        http_result = {"findings": [], "responses": [], "metadata": {"errors": [str(exc)]}}

    print("[*] Running TLS certificate/protocol inspection...")
    try:
        ssl_result = inspect_ssl(hostname, timeout=args.timeout)
        print_summary("TLS checker", ssl_result.get("findings", []))
    except Exception as exc:
        print(f"[!] TLS checker error: {exc}", file=sys.stderr)
        ssl_result = {
            "certificate": None,
            "protocols": [],
            "findings": [{
                "title": "TLS inspection failed",
                "severity": "Info",
                "description": str(exc),
                "remediation": "Verify that the target exposes HTTPS on TCP/443.",
                "owasp": "A02:2021 Cryptographic Failures",
            }],
        }

    report = build_report(
        target=args.target,
        hostname=hostname,
        started_at=timestamp,
        port_results=port_results,
        port_findings=port_findings,
        http_result=http_result,
        ssl_result=ssl_result,
    )

    try:
        path = write_report(report, args.output, args.format)
        print(f"[+] Report written to: {path}")
    except OSError as exc:
        print(f"[!] Could not write report: {exc}", file=sys.stderr)
        return 3

    counts = report["summary"]["severity_counts"]
    print(
        "[+] Final summary: "
        f"High={counts['High']} Medium={counts['Medium']} "
        f"Low={counts['Low']} Info={counts['Info']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
