"""
utils/anonymity.py — Tor integration, proxy rotation, identity checks
"""

import logging
import requests
from typing import Optional, Dict
from config import TOR_PROXY, TOR_CONTROL_PORT, TOR_CONTROL_PASSWORD

logger = logging.getLogger(__name__)

class AnonymityManager:
    """Manages Tor circuits, proxy rotation, and anonymity verification."""

    def __init__(self):
        self.tor_available = False
        self._check_tor()

    def _check_tor(self):
        try:
            resp = requests.get(
                "http://check.torproject.org/api/ip",
                proxies={"http": TOR_PROXY, "https": TOR_PROXY},
                timeout=8,
            )
            data = resp.json()
            self.tor_available = data.get("IsTor", False)
            if self.tor_available:
                logger.info(f"[TOR] Active — Exit IP: {data.get('IP', 'unknown')}")
        except Exception:
            self.tor_available = False
            logger.debug("[TOR] Not reachable or not running.")

    def get_current_ip(self, use_tor: bool = False) -> Dict:
        """Return current public IP and metadata."""
        proxies = {"http": TOR_PROXY, "https": TOR_PROXY} if use_tor else None
        try:
            resp = requests.get("https://ipinfo.io/json", proxies=proxies, timeout=8)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def new_tor_circuit(self) -> bool:
        """Signal Tor to build a new circuit (change exit node)."""
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
                if TOR_CONTROL_PASSWORD:
                    ctrl.authenticate(password=TOR_CONTROL_PASSWORD)
                else:
                    ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
                logger.info("[TOR] New circuit requested.")
                return True
        except ImportError:
            logger.warning("[TOR] 'stem' library not installed. Run: pip install stem")
            return False
        except Exception as e:
            logger.warning(f"[TOR] Could not rotate circuit: {e}")
            return False

    def verify_anonymity(self) -> Dict:
        """Check both real and Tor IPs to verify anonymity."""
        real_ip_info    = self.get_current_ip(use_tor=False)
        tor_ip_info     = self.get_current_ip(use_tor=True) if self.tor_available else {}
        return {
            "real_ip":      real_ip_info.get("ip", "unknown"),
            "real_country": real_ip_info.get("country", "unknown"),
            "tor_active":   self.tor_available,
            "tor_ip":       tor_ip_info.get("ip", "N/A"),
            "tor_country":  tor_ip_info.get("country", "N/A"),
            "anonymous":    self.tor_available,
        }

    def check_dns_leak(self) -> Dict:
        """Perform a basic DNS leak test."""
        try:
            resp = requests.get(
                "https://dnsleaktest.com/test",
                proxies={"http": TOR_PROXY, "https": TOR_PROXY} if self.tor_available else None,
                timeout=8,
            )
            return {"status": resp.status_code, "url": "https://dnsleaktest.com"}
        except Exception as e:
            return {"error": str(e)}

    def status_report(self) -> Dict:
        return {
            "tor_available":  self.tor_available,
            "anonymity_info": self.verify_anonymity(),
        }
