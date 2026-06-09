from typing import Dict, List, Optional
import logging

from .zap_client import ZapClient

# Mapping of interest alert names fragments for filtering
INTEREST_ALERTS = [
	"xss",           # Cross Site Scripting
	"cross-site scripting",
	"csrf",          # Cross-Site Request Forgery
	"cross-site request forgery",
	"sql injection",
]


class WebScanner:
	def __init__(
		self,
		zap_address: str = "127.0.0.1",
		zap_port: int = 8080,
		zap_api_key: Optional[str] = None,
		poll_seconds: float = 2.0,
	):
		self.client = ZapClient(zap_address, zap_port, zap_api_key, poll_seconds)

	def run_scan(self, target_url: str, enable_only_relevant: bool = False) -> List[Dict]:
		logging.info("Starting scan for %s", target_url)
		self.client.access_target(target_url)
		if enable_only_relevant:
			# Best-effort enabling of relevant scanners by name fragment
			self.client.enable_policies(["xss", "csrf", "sql injection"]) 
		self.client.spider(target_url)
		self.client.active_scan(target_url)
		alerts = self.client.get_alerts(target_url)
		logging.info("Total alerts returned by ZAP: %d", len(alerts))
		filtered = self._filter_relevant_alerts(alerts)
		logging.info("Filtered relevant alerts: %d", len(filtered))
		return filtered

	def _filter_relevant_alerts(self, alerts: List[Dict]) -> List[Dict]:
		filtered: List[Dict] = []
		for a in alerts:
			name = (a.get("alert") or "").lower()
			if any(keyword in name for keyword in INTEREST_ALERTS):
				filtered.append(a)
		return filtered
