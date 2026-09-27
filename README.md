# Web Security Assessment Toolkit v2

A modular Python CLI for a lightweight, authorized web security assessment.

## What's improved in v2

- Security headers are assessed primarily on the final HTTPS response.
- HSTS is not incorrectly reported as missing from HTTP.
- Duplicate HTTP/HTTPS header findings are removed.
- HTTP is checked for HTTPS redirect behavior.
- TLS certificate parsing uses Python/OpenSSL certificate decoding rather than relying on `getpeercert()` from an unverified TLS socket.
- Open ports remain informational; they are not automatically presented as confirmed vulnerabilities.
- Exposed-path results explicitly state that an HTTP 200 does not prove sensitive data disclosure.
- TLS inspection failures are reported as informational inspection limitations rather than automatically treated as TLS vulnerabilities.
- Reports retain raw technical data for manual validation.

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
python3 main.py \
  --target example.com \
  --ports 80,443,8080,8443 \
  --timeout 5 \
  --output report.html
```

## Report interpretation

The tool is intentionally conservative. A finding is an assessment indicator, not proof of exploitability.

Examples:

- Open TCP port → informational service exposure.
- Missing CSP → configuration weakness that should be evaluated in application context.
- `.env` returning 200 → potentially serious exposure indicator that must be manually validated.
- Certificate expiry → concrete TLS certificate condition.
- TLS protocol support → dependent on local Python/OpenSSL capabilities.

## OWASP Top 10 mappings

Applicable findings are mapped to:

- A02:2021 Cryptographic Failures
- A05:2021 Security Misconfiguration

## Ethical use

Only scan systems you own or have explicit permission to test. Do not use this project for unauthorized reconnaissance, exploitation, credential attacks, or disruptive activity.

## Limitations

This is not a replacement for a professional VAPT. It does not perform exploitation, password guessing, fuzzing, crawling, authenticated testing, or destructive actions.
