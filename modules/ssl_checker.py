"""TLS certificate and protocol inspector using Python ssl/socket."""

import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path

CRYPTO = "A02:2021 Cryptographic Failures"


def finding(title, severity, description, remediation):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "owasp": CRYPTO,
    }


def _name_to_text(name) -> str:
    parts = []
    for group in name or ():
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _certificate_to_dict(host: str, timeout: float):
    """
    Obtain the peer certificate from a normal TLS socket.

    A verification-disabled context is used only to retrieve the certificate.
    Hostname/trust validation is performed separately below.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            protocol = tls_sock.version()

    if not cert_der:
        raise ssl.SSLError("Server returned no certificate")

    pem = ssl.DER_cert_to_PEM_cert(cert_der)

    # Python's standard decoder works from a PEM file. This avoids
    # relying on the deprecated/removed ssl.match_hostname API.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False, encoding="ascii"
    ) as handle:
        handle.write(pem)
        cert_path = handle.name

    try:
        cert = ssl._ssl._test_decode_cert(cert_path)
    finally:
        Path(cert_path).unlink(missing_ok=True)

    return cert, protocol


def _hostname_matches(cert: dict, hostname: str) -> bool:
    """
    Validate SAN/CN against the hostname.

    ssl.match_hostname is not available in some newer Python versions,
    so use the documented ipaddress matching plus ssl internals only
    through the certificate data where necessary.
    """
    # Prefer stdlib helper when available.
    helper = getattr(ssl, "match_hostname", None)
    if helper is not None:
        try:
            helper(cert, hostname)
            return True
        except (ssl.CertificateError, ValueError):
            return False

    # Compatibility fallback for Python versions without ssl.match_hostname.
    import fnmatch
    import ipaddress

    names = [
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind == "DNS"
    ]
    ips = [
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind == "IP Address"
    ]

    try:
        requested_ip = ipaddress.ip_address(hostname)
        return any(
            ipaddress.ip_address(value) == requested_ip
            for value in ips
        )
    except ValueError:
        pass

    hostname_lower = hostname.lower().rstrip(".")
    for name in names:
        candidate = name.lower().rstrip(".")
        # RFC-style wildcard handling: wildcard covers one left-most label.
        if candidate.startswith("*."):
            suffix = candidate[1:]
            if hostname_lower.endswith(suffix) and hostname_lower.count(".") == candidate.count("."):
                return True
        elif fnmatch.fnmatchcase(hostname_lower, candidate):
            return True

    # CN fallback only when SAN is absent.
    if not names and not ips:
        for group in cert.get("subject", ()):
            for key, value in group:
                if key == "commonName":
                    candidate = value.lower().rstrip(".")
                    if candidate == hostname_lower:
                        return True
                    if candidate.startswith("*.") and hostname_lower.endswith(candidate[1:]):
                        return hostname_lower.count(".") == candidate.count(".")
    return False


def _check_protocol(host: str, version: ssl.TLSVersion, timeout: float) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


def inspect_ssl(host: str, timeout: float = 3.0) -> dict:
    result = {"certificate": None, "protocols": [], "findings": []}

    try:
        cert, negotiated = _certificate_to_dict(host, timeout)

        not_after = cert.get("notAfter")
        expiry = datetime.strptime(
            not_after, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_remaining = (expiry - now).total_seconds() / 86400

        subject = _name_to_text(cert.get("subject"))
        issuer = _name_to_text(cert.get("issuer"))
        san = [
            value
            for kind, value in cert.get("subjectAltName", ())
            if kind == "DNS"
        ]

        hostname_matches = _hostname_matches(cert, host)
        self_signed = bool(subject and issuer and subject == issuer)

        result["certificate"] = {
            "not_before": cert.get("notBefore"),
            "not_after": not_after,
            "days_remaining": round(days_remaining, 2),
            "issuer": issuer,
            "subject": subject,
            "subject_alt_names": san,
            "hostname_matches": hostname_matches,
            "self_signed_heuristic": self_signed,
            "negotiated_protocol": negotiated,
            "certificate_available": True,
        }

        if days_remaining < 0:
            result["findings"].append(
                finding(
                    "TLS certificate expired",
                    "High",
                    f"The certificate expired {abs(days_remaining):.1f} day(s) ago.",
                    "Replace the expired certificate with a valid certificate covering the target hostname.",
                )
            )
        elif days_remaining < 30:
            result["findings"].append(
                finding(
                    "TLS certificate expires soon",
                    "Medium",
                    f"The certificate has approximately {days_remaining:.1f} day(s) remaining.",
                    "Renew the certificate before its validity period ends.",
                )
            )

        if not hostname_matches:
            result["findings"].append(
                finding(
                    "TLS hostname mismatch",
                    "High",
                    "The certificate SAN/CN does not match the requested hostname.",
                    "Install a certificate whose SAN covers the hostname used by clients.",
                )
            )

        if self_signed:
            result["findings"].append(
                finding(
                    "Potential self-signed certificate",
                    "Medium",
                    "Certificate issuer and subject are identical; this is a heuristic indicator.",
                    "Use a certificate issued by a trusted CA for publicly accessible services.",
                )
            )

        for version, label in (
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ):
            supported = _check_protocol(host, version, timeout)
            result["protocols"].append({
                "protocol": label,
                "supported": supported,
            })
            if supported:
                result["findings"].append(
                    finding(
                        f"Deprecated protocol enabled: {label}",
                        "Medium",
                        f"The server completed a handshake using {label}.",
                        "Disable deprecated TLS protocols and require modern TLS versions.",
                    )
                )

        return result

    except (OSError, ssl.SSLError, ValueError) as exc:
        result["findings"].append(
            finding(
                "TLS inspection could not be completed",
                "Info",
                f"Certificate inspection failed: {exc}",
                "Verify that TCP/443 exposes TLS and retry from an environment with compatible OpenSSL support.",
            )
        )
        return result
