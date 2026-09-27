"""HTTP/HTTPS security-header, cookie and exposure analyzer."""

import re
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Medium",
        "Add a restrictive Content-Security-Policy appropriate for the application.",
    ),
    "Strict-Transport-Security": (
        "Medium",
        "Enable HSTS on the HTTPS response after confirming HTTPS is correctly deployed.",
    ),
    "X-Frame-Options": (
        "Low",
        "Set X-Frame-Options or an equivalent CSP frame-ancestors policy.",
    ),
    "X-Content-Type-Options": (
        "Low",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        "Low",
        "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "Low",
        "Set a restrictive Permissions-Policy for browser capabilities not required.",
    ),
}

MISCONFIG = "A05:2021 Security Misconfiguration"
CRYPTO = "A02:2021 Cryptographic Failures"


def finding(title, severity, description, remediation, owasp=MISCONFIG):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "owasp": owasp,
    }


def _header_findings(response: requests.Response, is_https: bool) -> list[dict]:
    findings = []

    for header, (severity, remediation) in SECURITY_HEADERS.items():
        # HSTS is meaningful only over HTTPS.
        if header == "Strict-Transport-Security" and not is_https:
            continue

        if header.lower() not in {key.lower() for key in response.headers.keys()}:
            findings.append(
                finding(
                    f"Missing security header: {header}",
                    severity,
                    f"{header} was not present in the final response from {response.url}.",
                    remediation,
                )
            )

    server = response.headers.get("Server", "")
    if re.search(r"/\d|[A-Za-z]+-\d", server):
        findings.append(
            finding(
                "Server version disclosure",
                "Low",
                f"The Server header appears to disclose implementation/version data: {server}",
                "Minimize server banner details at the web server or reverse proxy.",
            )
        )

    for cookie in response.cookies:
        rest = {str(k).lower(): str(v) for k, v in cookie._rest.items()}
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if "samesite" not in rest:
            missing.append("SameSite")

        if missing:
            findings.append(
                finding(
                    f"Cookie missing security flags: {cookie.name}",
                    "Medium",
                    f"Cookie {cookie.name!r} is missing: {', '.join(missing)}.",
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute on sensitive cookies.",
                )
            )

    return findings


def _probe_exposed_paths(session, origin: str, timeout: float) -> list[dict]:
    findings = []
    for path in ("/.git/", "/.env", "/admin", "/backup"):
        url = origin.rstrip("/") + path
        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            response.close()

            if status in {200, 206}:
                severity = "High" if path in {"/.git/", "/.env"} else "Medium"
                findings.append(
                    finding(
                        f"Potentially exposed path: {path}",
                        severity,
                        (
                            f"{url} returned HTTP {status}"
                            + (f" with Content-Type {content_type}." if content_type else ".")
                            + " This is an exposure indicator, not proof of sensitive data disclosure."
                        ),
                        "Remove or restrict administrative, backup, VCS, and environment files from the public web root.",
                    )
                )
        except requests.RequestException:
            continue
    return findings


def _dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in findings:
        key = (
            item.get("title"),
            item.get("severity"),
            item.get("description"),
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def analyze_http(hostname: str, base_url: str, timeout: float = 3.0) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": "Web-Security-Assessment-Toolkit/2.0"})

    findings = []
    responses = []
    errors = []

    parsed = urlparse(base_url)
    netloc = parsed.netloc or hostname
    http_url = f"http://{netloc}/"
    https_url = f"https://{netloc}/"

    http_response = None
    https_response = None

    # HTTP is checked primarily for redirect behavior.
    try:
        http_response = session.get(
            http_url,
            timeout=timeout,
            allow_redirects=False,
            verify=True,
        )
        responses.append({
            "requested_url": http_url,
            "final_url": http_response.url,
            "status_code": http_response.status_code,
            "server": http_response.headers.get("Server"),
            "redirect_location": http_response.headers.get("Location"),
        })
    except requests.RequestException as exc:
        errors.append({"url": http_url, "error": str(exc)})

    # HTTPS is the authoritative response for security-header checks.
    try:
        https_response = session.get(
            https_url,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        responses.append({
            "requested_url": https_url,
            "final_url": https_response.url,
            "status_code": https_response.status_code,
            "server": https_response.headers.get("Server"),
            "redirect_location": None,
        })
        findings.extend(_header_findings(https_response, is_https=True))
    except requests.exceptions.SSLError as exc:
        errors.append({"url": https_url, "error": f"TLS verification failed: {exc}"})
        findings.append(
            finding(
                "TLS certificate verification failed",
                "Medium",
                f"Requests could not verify the certificate while fetching {https_url}.",
                "Install a certificate trusted by the client trust store and ensure the hostname matches.",
                CRYPTO,
            )
        )
    except requests.RequestException as exc:
        errors.append({"url": https_url, "error": str(exc)})

    # HTTP transport enforcement is a separate configuration check.
    # This is intentionally Low: an HTTP endpoint is not automatically a
    # vulnerability unless the application requires HTTPS-only access.
    if http_response is not None and 200 <= http_response.status_code < 400:
        location = http_response.headers.get("Location", "")
        if not location.lower().startswith("https://"):
            findings.append(
                finding(
                    "HTTP endpoint does not enforce HTTPS redirect",
                    "Low",
                    (
                        f"{http_url} returned HTTP {http_response.status_code} "
                        "without a direct HTTPS Location header."
                    ),
                    "If the application is HTTPS-only, redirect HTTP requests to HTTPS and use HSTS on HTTPS responses.",
                    CRYPTO,
                )
            )

    # Probe the final HTTPS origin when available.
    if https_response is not None:
        probe_origin = f"{urlparse(https_response.url).scheme}://{urlparse(https_response.url).netloc}"
    else:
        probe_origin = f"https://{netloc}"

    findings.extend(_probe_exposed_paths(session, probe_origin, timeout))

    return {
        "findings": _dedupe(findings),
        "responses": responses,
        "metadata": {"errors": errors},
    }
