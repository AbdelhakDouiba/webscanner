# WebScanner (OWASP ZAP)

A minimal, structured Python tool to scan a target for XSS, CSRF, and SQL Injection using the OWASP ZAP API. Generates an HTML report with findings.

## Prerequisites

- OWASP ZAP running in daemon/headless mode or the desktop app with API enabled.
  - Example (daemon):
    - Linux/macOS: `zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true`
    - Windows (PowerShell): `& "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true`
- Python 3.9+

## Setup

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Start ZAP first (daemon or desktop with API enabled), then run:

```
python cli.py --target https://example.com --only-relevant --out reports -v
```

Key options:
- `--zap-address` and `--zap-port` to point to your ZAP instance (default `127.0.0.1:8080`).
- `--zap-api-key` if ZAP requires an API key.
- `--only-relevant` tries to enable XSS/CSRF/SQLi scanners only (best-effort).

Reports are written to `reports/report.html`.

## Notes

- This focuses on XSS, CSRF and SQL Injection. Other alerts are ignored in the final report.
- Some scanner names can vary by ZAP version; filtering is done post-scan by alert name and risk.
- For authenticated or complex apps, you may need to augment spidering or context/session setup.
