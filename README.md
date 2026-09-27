# Web Security Assessment Toolkit v3

A modular Python CLI for a lightweight, authorized web security assessment.

## What's improved in v3

- Fixed TLS hostname validation compatibility for Python versions where `ssl.match_hostname` is unavailable.
- TLS certificate information is now intended to populate instead of incorrectly returning `certificate: null` because of the removed helper.
- Certificate expiry, issuer, subject, SANs, hostname matching, negotiated protocol, and self-signed heuristic are reported separately.
- Deprecated TLS 1.0/1.1 checks remain best-effort and depend on the local OpenSSL build.
- HTTP-to-HTTPS enforcement is now a **Low** configuration finding rather than automatically a Medium finding.
- The HTTPS response remains the authoritative response for security-header checks.
- HSTS is never assessed from the HTTP response.
- Duplicate header findings are removed.
- Open ports remain informational service-exposure results.
- Exposed-path results explicitly state that HTTP 200 does not prove sensitive data disclosure.
- TLS inspection failures remain informational inspection limitations.


## 🔄 Version History

### v1.0 — Initial Release
- TCP port scanner for common ports
- HTTP/HTTPS security header analysis
- SSL/TLS certificate checks
- JSON and HTML report generation
- OWASP Top 10 mapping
- CLI interface

### v2.0 — Analysis Improvements
- Reduced duplicate HTTP/HTTPS findings
- HSTS checked only on HTTPS
- Improved TLS certificate extraction
- Improved exposed-path reporting
- Improved HTTP → HTTPS detection
- Cleaner report output

### v3.0 — TLS & Validation Improvements
- Fixed TLS hostname validation compatibility
- Added SAN and hostname matching
- Improved certificate parsing
- Added negotiated TLS protocol detection
- Improved self-signed certificate detection
- Refined severity and remediation messages
- Cleaner and more reliable security reports


## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py --target example.com --output report.html
```

JSON:

```bash
python3 main.py --target example.com --output report.json --format json
```

Custom ports:

```bash
python3 main.py --target example.com --ports 80,443,8080,8443 --timeout 5 --output report.html
```
The current toolkit is not scanning all 65,535 ports. It is currently doing a common-port scan, it scans only these 13 TCP ports:

**[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]**

## Report interpretation

The tool is intentionally conservative. A finding is an assessment indicator, not proof of exploitability.

Examples:

- Open TCP port → informational service exposure.
- Missing CSP → configuration weakness that should be evaluated in application context.
- `.env` returning 200 → potentially serious exposure indicator that must be manually validated.
- Certificate expiry → concrete TLS certificate condition.
- TLS protocol support → dependent on local Python/OpenSSL capabilities.


## Expected TLS output

A successful TLS inspection should populate data similar to:

```json
{
  "certificate": {
    "not_after": "...",
    "days_remaining": 60,
    "issuer": "...",
    "subject": "...",
    "subject_alt_names": ["example.com"],
    "hostname_matches": true,
    "self_signed_heuristic": false,
    "negotiated_protocol": "TLSv1.3",
    "certificate_available": true
  }
}
```

Exact values depend on the target and the local Python/OpenSSL environment.

## OWASP Top 10 mappings

Applicable findings are mapped to:

- A02:2021 Cryptographic Failures
- A05:2021 Security Misconfiguration

## Ethical use

Only scan systems you own or have explicit permission to test. Do not use this project for unauthorized reconnaissance, exploitation, credential attacks, or disruptive activity.

## Limitations

This is not a replacement for a professional VAPT. It does not perform exploitation, password guessing, fuzzing, crawling, authenticated testing, or destructive actions.
