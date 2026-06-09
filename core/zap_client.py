from typing import List, Dict, Optional
import time
import logging
from urllib.parse import urlparse

from zapv2 import ZAPv2


class ZapClient:
	def __init__(
		self,
		zap_address: str = "127.0.0.1",
		zap_port: int = 8080,
		zap_api_key: Optional[str] = None,
		poll_seconds: float = 2.0,
	):
		self.address = zap_address
		self.port = zap_port
		self.api_key = zap_api_key or ""
		self.poll_seconds = poll_seconds
		self._zap = ZAPv2(apikey=self.api_key, proxies={
			"http": f"http://{self.address}:{self.port}",
			"https": f"http://{self.address}:{self.port}",
		})

	def _wait_for_spider(self, scan_id: str) -> None:
		while True:
			status = int(self._zap.spider.status(scan_id))
			logging.debug("Spider status: %s", status)
			if status >= 100:
				break
			time.sleep(self.poll_seconds)

	def _wait_for_active_scan(self, scan_id: str) -> None:
		while True:
			status = int(self._zap.ascan.status(scan_id))
			logging.debug("Active scan status: %s", status)
			if status >= 100:
				break
			time.sleep(self.poll_seconds)

	def access_target(self, url: str) -> None:
		self._zap.urlopen(url)
		time.sleep(1)

	def spider(self, url: str, max_children: Optional[int] = None, recurse: bool = True) -> None:
		parsed = urlparse(url)
		if not parsed.scheme or not parsed.netloc:
			raise ValueError("URL must include scheme and host, e.g., https://example.com")
		scan_id = self._zap.spider.scan(url, maxchildren=max_children or 0, recurse=str(recurse).lower())
		self._wait_for_spider(scan_id)

	def active_scan(self, url: str, policy: Optional[str] = None) -> None:
		scan_id = self._zap.ascan.scan(url, recurse=True, scanpolicyname=policy or "")
		self._wait_for_active_scan(scan_id)

	def get_alerts(self, base_url: str) -> List[Dict]:
		return self._zap.core.alerts(baseurl=base_url, start=None, count=None)

	def enable_policies(self, policy_names: List[str]) -> None:
		# Ensure only specific policies are enabled (best-effort; requires policy names in ZAP)
		policies = self._zap.ascan.scanners()
		# Disable all first
		for p in policies:
			if p.get("enabled") == "true":
				self._zap.ascan.set_scanner_alert_threshold(p["id"], "off")
		# Enable requested
		for p in policies:
			name = p.get("name", "").lower()
			if any(target.lower() in name for target in policy_names):
				self._zap.ascan.set_scanner_alert_threshold(p["id"], "default")
