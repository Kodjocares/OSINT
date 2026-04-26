"""
modules/ip_classifier.py — VPN, proxy, Tor exit node, and datacenter IP detection
Classify IPs as residential, datacenter, VPN, proxy, or Tor exit
"""

import logging
from typing import Dict, List
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

TOR_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"
IPQS_API      = "https://ipqualityscore.com/api/json/ip"
IPAPI_CO      = "https://ipapi.co"


class IPClassifier:
    """Classify IP addresses — VPN, proxy, Tor, datacenter, or residential."""

    def __init__(self, ipqs_key: str = "", abuseipdb_key: str = ""):
        self.ipqs_key      = ipqs_key
        self.abuseipdb_key = abuseipdb_key
        self._tor_exits    = set()

    # ──────────────────────────────────────────────────────────
    # TOR EXIT NODES
    # ──────────────────────────────────────────────────────────
    def _load_tor_exits(self) -> set:
        if self._tor_exits:
            return self._tor_exits
        resp = safe_request(TOR_EXIT_LIST)
        if resp and resp.status_code == 200:
            self._tor_exits = set(
                line.strip() for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            )
        return self._tor_exits

    def is_tor_exit(self, ip: str) -> bool:
        exits = self._load_tor_exits()
        return ip in exits

    # ──────────────────────────────────────────────────────────
    # IPAPI.CO classification (free)
    # ──────────────────────────────────────────────────────────
    def _ipapi_classify(self, ip: str) -> Dict:
        resp = safe_request(f"{IPAPI_CO}/{ip}/json/")
        if resp and resp.status_code == 200:
            d = resp.json()
            return {
                "ip":      ip,
                "org":     d.get("org"),
                "asn":     d.get("asn"),
                "city":    d.get("city"),
                "country": d.get("country_name"),
                "timezone":d.get("timezone"),
            }
        return {}

    # ──────────────────────────────────────────────────────────
    # IPQUALITYSCORE (requires free key)
    # ──────────────────────────────────────────────────────────
    def _ipqs_classify(self, ip: str) -> Dict:
        if not self.ipqs_key:
            return {}
        resp = safe_request(f"{IPQS_API}/{self.ipqs_key}/{ip}")
        if resp and resp.status_code == 200:
            d = resp.json()
            return {
                "fraud_score":       d.get("fraud_score", 0),
                "is_vpn":            d.get("vpn", False),
                "is_proxy":          d.get("proxy", False),
                "is_tor":            d.get("tor", False),
                "is_bot":            d.get("bot_status", False),
                "recent_abuse":      d.get("recent_abuse", False),
                "connection_type":   d.get("connection_type"),
                "abuse_velocity":    d.get("abuse_velocity"),
                "isp":               d.get("ISP"),
                "organization":      d.get("organization"),
                "mobile":            d.get("mobile", False),
            }
        return {}

    # ──────────────────────────────────────────────────────────
    # ABUSEIPDB
    # ──────────────────────────────────────────────────────────
    def _abuseipdb_check(self, ip: str) -> Dict:
        if not self.abuseipdb_key:
            return {}
        resp = safe_request(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
        )
        if resp and resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "abuse_confidence": d.get("abuseConfidenceScore"),
                "total_reports":    d.get("totalReports"),
                "last_reported":    d.get("lastReportedAt"),
                "isp":              d.get("isp"),
                "usage_type":       d.get("usageType"),
                "is_tor":           d.get("isTor"),
                "is_public":        d.get("isPublic"),
                "domain":           d.get("domain"),
            }
        return {}

    # ──────────────────────────────────────────────────────────
    # DATACENTER DETECTION
    # ──────────────────────────────────────────────────────────
    def _is_likely_datacenter(self, org: str) -> bool:
        dc_keywords = [
            "amazon", "aws", "google", "azure", "microsoft", "digitalocean",
            "linode", "vultr", "hetzner", "ovh", "cloudflare", "fastly",
            "akamai", "leaseweb", "choopa", "psychz", "hurricane electric",
            "cogent", "level3", "zayo", "hosting", "datacenter", "data center",
            "colocation", "colo", "server", "cloud",
        ]
        org_lower = (org or "").lower()
        return any(kw in org_lower for kw in dc_keywords)

    # ──────────────────────────────────────────────────────────
    # MAIN CLASSIFY
    # ──────────────────────────────────────────────────────────
    def classify(self, ip: str) -> Dict:
        """Full IP classification report."""
        result = {
            "ip":              ip,
            "is_tor":          False,
            "is_vpn":          False,
            "is_proxy":        False,
            "is_datacenter":   False,
            "is_residential":  False,
            "is_mobile":       False,
            "fraud_score":     0,
            "abuse_confidence":0,
            "classification":  "unknown",
            "risk_level":      "UNKNOWN",
            "details":         {},
        }

        # Tor check (free)
        result["is_tor"] = self.is_tor_exit(ip)

        # ipapi.co base info
        ipapi_data = self._ipapi_classify(ip)
        result["details"]["ipapi"] = ipapi_data
        org = ipapi_data.get("org", "")
        result["is_datacenter"] = self._is_likely_datacenter(org)

        # IPQS (if key provided)
        ipqs_data = self._ipqs_classify(ip)
        if ipqs_data:
            result["details"]["ipqs"]  = ipqs_data
            result["is_vpn"]           = ipqs_data.get("is_vpn", False)
            result["is_proxy"]         = ipqs_data.get("is_proxy", False)
            result["is_tor"]           = result["is_tor"] or ipqs_data.get("is_tor", False)
            result["is_mobile"]        = ipqs_data.get("mobile", False)
            result["fraud_score"]      = ipqs_data.get("fraud_score", 0)

        # AbuseIPDB (if key provided)
        abuse_data = self._abuseipdb_check(ip)
        if abuse_data:
            result["details"]["abuseipdb"] = abuse_data
            result["abuse_confidence"]     = abuse_data.get("abuse_confidence", 0)
            result["is_tor"]               = result["is_tor"] or abuse_data.get("is_tor", False)

        # Derive classification
        if result["is_tor"]:
            result["classification"] = "tor_exit_node"
            result["risk_level"]     = "HIGH"
        elif result["is_vpn"]:
            result["classification"] = "vpn"
            result["risk_level"]     = "MEDIUM"
        elif result["is_proxy"]:
            result["classification"] = "proxy"
            result["risk_level"]     = "MEDIUM"
        elif result["is_datacenter"]:
            result["classification"] = "datacenter"
            result["risk_level"]     = "LOW"
        elif result["is_mobile"]:
            result["classification"] = "mobile_carrier"
            result["risk_level"]     = "LOW"
        else:
            result["classification"] = "residential"
            result["risk_level"]     = "LOW"

        if result["abuse_confidence"] > 50:
            result["risk_level"] = "HIGH"
        if result["fraud_score"] > 75:
            result["risk_level"] = "CRITICAL"

        return result

    # ──────────────────────────────────────────────────────────
    # BULK CLASSIFY
    # ──────────────────────────────────────────────────────────
    def classify_bulk(self, ips: List[str]) -> List[Dict]:
        return [self.classify(ip) for ip in ips]
