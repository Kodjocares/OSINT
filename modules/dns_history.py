"""
modules/dns_history.py — Historical DNS & passive DNS intelligence
SecurityTrails, HackerTarget, ViewDNS.info for historical records
"""

import logging
from typing import Dict, List
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)

HACKERTARGET_API = "https://api.hackertarget.com"
VIEWDNS_API      = "https://viewdns.info/api"


class DNSHistory:
    """Historical DNS lookups — track infrastructure changes over time."""

    def __init__(self, securitytrails_key: str = "", viewdns_key: str = ""):
        self.st_key      = securitytrails_key
        self.viewdns_key = viewdns_key

    # ──────────────────────────────────────────────────────────
    # HACKERTARGET (free, no key)
    # ──────────────────────────────────────────────────────────
    def hackertarget_dns_lookup(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        results = {}
        endpoints = {
            "a_records":    f"{HACKERTARGET_API}/dnslookup/?q={domain}",
            "mx_records":   f"{HACKERTARGET_API}/mxlookup/?q={domain}",
            "hostsearch":   f"{HACKERTARGET_API}/hostsearch/?q={domain}",
            "reverse_ip":   f"{HACKERTARGET_API}/reverseiplookup/?q={domain}",
            "zone_transfer":f"{HACKERTARGET_API}/zonetransfer/?q={domain}",
        }
        for record_type, url in endpoints.items():
            resp = safe_request(url)
            if resp and resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                results[record_type] = [
                    line.strip() for line in resp.text.splitlines() if line.strip()
                ]
            else:
                results[record_type] = []

        return {"domain": domain, "hackertarget": results}

    # ──────────────────────────────────────────────────────────
    # SECURITYTRAILS (requires free API key)
    # ──────────────────────────────────────────────────────────
    def securitytrails_history(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        if not self.st_key:
            return {
                "domain": domain,
                "note":   "SecurityTrails key not configured. Sign up free at securitytrails.com",
                "signup": "https://securitytrails.com/corp/api",
            }

        headers = {"APIKEY": self.st_key, "Accept": "application/json"}
        result  = {"domain": domain, "history": {}, "current": {}, "subdomains": []}

        # Current DNS
        cur = safe_request(f"https://api.securitytrails.com/v1/domain/{domain}",
                           headers=headers)
        if cur and cur.status_code == 200:
            result["current"] = cur.json()

        # DNS history
        for record_type in ["a", "mx", "ns", "txt", "cname"]:
            hist = safe_request(
                f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}",
                headers=headers
            )
            if hist and hist.status_code == 200:
                result["history"][record_type] = hist.json().get("records", [])

        # Subdomains
        sub = safe_request(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                           headers=headers)
        if sub and sub.status_code == 200:
            subs = sub.json().get("subdomains", [])
            result["subdomains"] = [f"{s}.{domain}" for s in subs]

        return result

    # ──────────────────────────────────────────────────────────
    # VIEWDNS.INFO (free / paid)
    # ──────────────────────────────────────────────────────────
    def ip_history(self, domain: str) -> Dict:
        """Get historical IPs a domain has resolved to."""
        domain = clean_domain(domain)

        # Try free ViewDNS web scrape
        resp = safe_request(
            f"https://viewdns.info/iphistory/?domain={domain}",
            headers={"Accept": "text/html"}
        )
        ips = []
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            for row in soup.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 3:
                    ip   = cells[0].get_text(strip=True)
                    loc  = cells[1].get_text(strip=True)
                    date = cells[2].get_text(strip=True)
                    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
                        ips.append({"ip": ip, "location": loc, "last_seen": date})

        return {"domain": domain, "ip_history": ips, "unique_ips": len(ips)}

    def reverse_ip_lookup(self, ip: str) -> Dict:
        """Find all domains that have pointed to an IP address."""
        resp = safe_request(f"{HACKERTARGET_API}/reverseiplookup/?q={ip}")
        domains = []
        if resp and resp.status_code == 200 and "error" not in resp.text[:50].lower():
            domains = [d.strip() for d in resp.text.splitlines() if d.strip()]

        return {
            "ip":           ip,
            "domains":      domains,
            "domain_count": len(domains),
            "note":         "Domains that currently or previously pointed to this IP",
        }

    # ──────────────────────────────────────────────────────────
    # FULL HISTORY REPORT
    # ──────────────────────────────────────────────────────────
    def full_history(self, domain: str) -> Dict:
        return {
            "domain":       domain,
            "hackertarget": self.hackertarget_dns_lookup(domain),
            "ip_history":   self.ip_history(domain),
            "securitytrails": self.securitytrails_history(domain),
        }

import re
