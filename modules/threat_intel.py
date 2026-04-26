"""
modules/threat_intel.py — Threat intelligence and IOC analysis
AlienVault OTX, VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus
"""

import hashlib
import logging
from typing import Dict, List, Optional
from utils.helpers import safe_request
from config import VIRUSTOTAL_API_KEY

logger = logging.getLogger(__name__)

OTX_API       = "https://otx.alienvault.com/api/v1"
ABUSE_API     = "https://api.abuseipdb.com/api/v2"
MALWARE_BAZAR = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API   = "https://urlhaus-api.abuse.ch/v1"
VT_API        = "https://www.virustotal.com/api/v3"


class ThreatIntel:
    """Multi-source threat intelligence — IOC lookup and reputation analysis."""

    def __init__(self, otx_key: str = "", abuseipdb_key: str = ""):
        self.otx_key      = otx_key
        self.abuseipdb_key = abuseipdb_key

    def _otx_headers(self) -> Dict:
        h = {"Accept": "application/json"}
        if self.otx_key:
            h["X-OTX-API-KEY"] = self.otx_key
        return h

    # ──────────────────────────────────────────────────────────
    # IP REPUTATION
    # ──────────────────────────────────────────────────────────
    def ip_reputation(self, ip: str) -> Dict:
        result = {"ip": ip, "otx": {}, "virustotal": {}, "abuseipdb": {}}

        # OTX
        resp = safe_request(f"{OTX_API}/indicators/IPv4/{ip}/general",
                            headers=self._otx_headers())
        if resp and resp.status_code == 200:
            d = resp.json()
            result["otx"] = {
                "pulse_count":   d.get("pulse_info", {}).get("count", 0),
                "reputation":    d.get("reputation", 0),
                "country":       d.get("country_name"),
                "asn":           d.get("asn"),
                "tags":          [p.get("name") for p in
                                  d.get("pulse_info", {}).get("pulses", [])[:5]],
                "malware_families": list(set(
                    t for p in d.get("pulse_info", {}).get("pulses", [])
                    for t in p.get("malware_families", [])
                )),
            }

        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            vt_resp = safe_request(f"{VT_API}/ip_addresses/{ip}",
                                   headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if vt_resp and vt_resp.status_code == 200:
                attrs = vt_resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["virustotal"] = {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "harmless":    stats.get("harmless", 0),
                    "reputation":  attrs.get("reputation", 0),
                    "country":     attrs.get("country"),
                    "asn":         attrs.get("asn"),
                    "tags":        attrs.get("tags", []),
                }

        # AbuseIPDB
        if self.abuseipdb_key:
            abuse_resp = safe_request(
                f"{ABUSE_API}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            if abuse_resp and abuse_resp.status_code == 200:
                d = abuse_resp.json().get("data", {})
                result["abuseipdb"] = {
                    "abuse_confidence": d.get("abuseConfidenceScore"),
                    "total_reports":    d.get("totalReports"),
                    "last_reported":    d.get("lastReportedAt"),
                    "isp":              d.get("isp"),
                    "usage_type":       d.get("usageType"),
                    "domain":           d.get("domain"),
                    "is_tor":           d.get("isTor"),
                }

        result["risk_summary"] = self._calculate_risk(result)
        return result

    # ──────────────────────────────────────────────────────────
    # DOMAIN REPUTATION
    # ──────────────────────────────────────────────────────────
    def domain_reputation(self, domain: str) -> Dict:
        result = {"domain": domain, "otx": {}, "virustotal": {}, "urlhaus": {}}

        # OTX
        resp = safe_request(f"{OTX_API}/indicators/domain/{domain}/general",
                            headers=self._otx_headers())
        if resp and resp.status_code == 200:
            d = resp.json()
            result["otx"] = {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "malware_families": list(set(
                    t for p in d.get("pulse_info", {}).get("pulses", [])
                    for t in p.get("malware_families", [])
                )),
                "alexa_rank": d.get("alexa"),
            }

        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            vt_resp = safe_request(f"{VT_API}/domains/{domain}",
                                   headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if vt_resp and vt_resp.status_code == 200:
                attrs = vt_resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["virustotal"] = {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "tags":       attrs.get("tags", []),
                }

        # URLhaus
        uh_resp = safe_request(f"{URLHAUS_API}/host/", json_data={"host": domain})
        if uh_resp and uh_resp.status_code == 200:
            d = uh_resp.json()
            result["urlhaus"] = {
                "query_status": d.get("query_status"),
                "urlhaus_reference": d.get("urlhaus_reference"),
                "urls_count": len(d.get("urls", [])),
                "blacklists":  d.get("blacklists", {}),
            }

        return result

    # ──────────────────────────────────────────────────────────
    # FILE HASH LOOKUP
    # ──────────────────────────────────────────────────────────
    def file_hash_lookup(self, file_hash: str) -> Dict:
        """Look up a file hash (MD5/SHA1/SHA256) against threat databases."""
        result = {"hash": file_hash, "hash_type": self._detect_hash_type(file_hash),
                  "virustotal": {}, "malwarebazaar": {}}

        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            vt_resp = safe_request(f"{VT_API}/files/{file_hash}",
                                   headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if vt_resp and vt_resp.status_code == 200:
                attrs = vt_resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["virustotal"] = {
                    "malicious":    stats.get("malicious", 0),
                    "suspicious":   stats.get("suspicious", 0),
                    "harmless":     stats.get("harmless", 0),
                    "file_name":    attrs.get("meaningful_name"),
                    "file_type":    attrs.get("magic"),
                    "file_size":    attrs.get("size"),
                    "md5":          attrs.get("md5"),
                    "sha1":         attrs.get("sha1"),
                    "sha256":       attrs.get("sha256"),
                    "first_seen":   attrs.get("first_submission_date"),
                    "last_seen":    attrs.get("last_submission_date"),
                    "tags":         attrs.get("tags", []),
                }

        # MalwareBazaar
        mb_resp = safe_request(MALWARE_BAZAR,
                               json_data={"query": "get_info", "hash": file_hash})
        if mb_resp and mb_resp.status_code == 200:
            d = mb_resp.json()
            if d.get("query_status") == "ok" and d.get("data"):
                sample = d["data"][0]
                result["malwarebazaar"] = {
                    "file_name":    sample.get("file_name"),
                    "file_type":    sample.get("file_type"),
                    "file_size":    sample.get("file_size"),
                    "malware_family":sample.get("signature"),
                    "tags":         sample.get("tags", []),
                    "first_seen":   sample.get("first_seen"),
                    "reporter":     sample.get("reporter"),
                }

        result["is_malicious"] = (
            result["virustotal"].get("malicious", 0) > 0
            or bool(result["malwarebazaar"].get("malware_family"))
        )
        return result

    # ──────────────────────────────────────────────────────────
    # URL ANALYSIS
    # ──────────────────────────────────────────────────────────
    def url_analysis(self, url: str) -> Dict:
        result = {"url": url, "urlhaus": {}, "virustotal": {}}

        # URLhaus
        uh_resp = safe_request(f"{URLHAUS_API}/url/", json_data={"url": url})
        if uh_resp and uh_resp.status_code == 200:
            result["urlhaus"] = uh_resp.json()

        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            vt_resp = safe_request(f"{VT_API}/urls/{url_id}",
                                   headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if vt_resp and vt_resp.status_code == 200:
                attrs = vt_resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["virustotal"] = {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "categories": attrs.get("categories", {}),
                    "final_url":  attrs.get("last_final_url"),
                    "title":      attrs.get("title"),
                }
        return result

    # ──────────────────────────────────────────────────────────
    # OTX PULSE SEARCH
    # ──────────────────────────────────────────────────────────
    def search_otx_pulses(self, query: str) -> Dict:
        """Search AlienVault OTX threat intelligence pulses."""
        resp = safe_request(
            f"{OTX_API}/search/pulses",
            params={"q": query, "limit": 10},
            headers=self._otx_headers(),
        )
        pulses = []
        if resp and resp.status_code == 200:
            for p in resp.json().get("results", []):
                pulses.append({
                    "name":             p.get("name"),
                    "description":      p.get("description", "")[:200],
                    "author":           p.get("author_name"),
                    "created":          p.get("created"),
                    "modified":         p.get("modified"),
                    "tags":             p.get("tags", []),
                    "malware_families": p.get("malware_families", []),
                    "indicator_count":  p.get("indicator_count", 0),
                    "tlp":              p.get("tlp"),
                })
        return {"query": query, "pulse_count": len(pulses), "pulses": pulses}

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────
    def _detect_hash_type(self, h: str) -> str:
        return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(h), "unknown")

    def _calculate_risk(self, result: Dict) -> str:
        score = 0
        score += min(result.get("otx", {}).get("pulse_count", 0) * 5, 40)
        score += result.get("virustotal", {}).get("malicious", 0) * 2
        abuse_conf = result.get("abuseipdb", {}).get("abuse_confidence", 0)
        score += abuse_conf // 5
        if score >= 50:   return "CRITICAL"
        elif score >= 30: return "HIGH"
        elif score >= 10: return "MEDIUM"
        elif score > 0:   return "LOW"
        return "CLEAN"
