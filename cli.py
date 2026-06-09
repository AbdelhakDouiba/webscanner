import logging
from pathlib import Path
from typing import Optional

import click

from webscanner.scanner import WebScanner
from webscanner.report import render_html


@click.command()
@click.option("--target", required=True, help="Target URL to scan, e.g., https://example.com")
@click.option("--zap-address", default="127.0.0.1", show_default=True)
@click.option("--zap-port", default=8080, type=int, show_default=True)
@click.option("--zap-api-key", default=None, help="API key if ZAP is configured with one")
@click.option("--only-relevant", is_flag=True, default=False, help="Enable only XSS/CSRF/SQLi scanners when possible")
@click.option("--out", "out_dir", default="reports", show_default=True, help="Output directory for reports")
@click.option("-v", "--verbose", is_flag=True, default=False)
def main(
	target: str,
	zap_address: str,
	zap_port: int,
	zap_api_key: Optional[str],
	only_relevant: bool,
	out_dir: str,
	verbose: bool,
) -> None:
	"""Run a focused scan for XSS, CSRF and SQL Injection using OWASP ZAP."""
	logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(levelname)s: %(message)s")

	scanner = WebScanner(zap_address=zap_address, zap_port=zap_port, zap_api_key=zap_api_key)
	alerts = scanner.run_scan(target, enable_only_relevant=only_relevant)

	out_dir_path = Path(out_dir)
	out_dir_path.mkdir(parents=True, exist_ok=True)
	out_html = out_dir_path / "report.html"
	render_html(alerts, target, str(out_html))
	click.echo(f"HTML report written to: {out_html}")


if __name__ == "__main__":
	main()
