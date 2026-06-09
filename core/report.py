from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _env(templates_dir: str) -> Environment:
	return Environment(
		loader=FileSystemLoader(templates_dir),
		autoescape=select_autoescape(["html", "xml"]),
		trim_blocks=True,
		lstrip_blocks=True,
	)


def render_html(
	alerts: List[Dict],
	target_url: str,
	out_html_path: str,
	templates_dir: Optional[str] = None,
) -> str:
	templates_dir = templates_dir or str(Path(__file__).parent.parent / "templates")
	Path(out_html_path).parent.mkdir(parents=True, exist_ok=True)
	env = _env(templates_dir)
	template = env.get_template("report.html.j2")
	sev_order = {"high": 3, "medium": 2, "low": 1, "info": 0}
	alerts_sorted = sorted(alerts, key=lambda a: sev_order.get((a.get("risk") or "").lower(), -1), reverse=True)
	html = template.render(
		target_url=target_url,
		scanned_at=datetime.utcnow().isoformat(timespec="seconds") + "Z",
		count=len(alerts_sorted),
		alerts=alerts_sorted,
	)
	Path(out_html_path).write_text(html, encoding="utf-8")
	return out_html_path
