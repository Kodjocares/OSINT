"""
modules/cert_transparency.py — Certificate Transparency intelligence
crt.sh, Censys CT logs, Facebook CT, certificate history & monitoring
"""

import re
import json
import logging
from typing import Dict, List, Set
from datetime import datetime
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)

CRT_SH_API = "https://crt.sh"


class CertTransparency:
    """
    Mine Certificate Transparency logs for subdomains, org intel,
    wildcard detection, and certificate history.
    """

    def __init__(self, censys_id: str = "", censys_secret: str = ""):
        self.censys_id     = censys_id
        self.censys_secret = censys_secret

    # ──────────────────────────────────────────────────────────
    # CRT.SH — core CT log query (free, no key)
    # ──────────────────────────────────────────────────────────
    def crtsh_search(self, domain: str, dedupe: bool = True) -> Dict:
        """Query crt.sh for all certificates issued to a domain."""
        domain = clean_domain(domain)

        # Wildcard search catches subdomains
        resp = safe_request(
            CRT_SH_API,
            params={"q": f"%.{domain}", "output": "json"}
        )
        if not resp or resp.status_code != 200:
            return {"domain": domain, "error": "crt.sh unavailable"}

        try:
            certs = resp.json()
        except Exception:
            return {"domain": domain, "error": "crt.sh parse error"}

        subdomains: Set[str] = set()
        issuers:    Set[str] = set()
        wildcard_certs = []
        cert_list      = []

        for cert in certs:
            # Extract all names from the certificate
            name_value = cert.get("name_value", "")
            for name in name_value.replace("\n", ",").split(","):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subdomains.add(name)
            # Track issuers
            issuer = cert.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)
            # Flag wildcards
            if "*." in cert.get("name_value",""):
                wildcard_certs.append({
                    "name":    cert.get("name_value"),
                    "issuer":  cert.get("issuer_name"),
                    "not_before": cert.get("not_before"),
                    "not_after":  cert.get("not_after"),
                    "id":         cert.get("id"),
                })
            cert_list.append({
                "id":         cert.get("id"),
                "logged_at":  cert.get("entry_timestamp"),
                "not_before": cert.get("not_before"),
                "not_after":  cert.get("not_after"),
                "issuer":     cert.get("issuer_name","")[:80],
                "names":      cert.get("name_value","")[:200],
            })

        # Sort subdomains
        sorted_subs = sorted(subdomains)

        return {
            "domain":           domain,
            "total_certs":      len(certs),
            "unique_subdomains":len(sorted_subs),
            "subdomains":       sorted_subs,
            "wildcard_certs":   wildcard_certs[:10],
            "issuers":          list(issuers)[:10],
            "latest_certs":     sorted(cert_list,
                                       key=lambda x: x.get("logged_at",""),
                                       reverse=True)[:20],
            "first_cert":       cert_list[-1].get("not_before") if cert_list else None,
            "newest_cert":      cert_list[0].get("not_after") if cert_list else None,
        }

    # ──────────────────────────────────────────────────────────
    # ORGANISATION SEARCH
    # ──────────────────────────────────────────────────────────
    def org_cert_search(self, org_name: str) -> Dict:
        """Find all certificates issued to an organisation name."""
        resp = safe_request(
            CRT_SH_API,
            params={"q": org_name, "output": "json"}
        )
        if not resp or resp.status_code != 200:
            return {"org": org_name, "error": "crt.sh unavailable"}

        try:
            certs = resp.json()
        except Exception:
            return {"org": org_name, "error": "Parse error"}

        domains:  Set[str] = set()
        issuers:  Set[str] = set()

        for cert in certs:
            name_value = cert.get("name_value","")
            for name in name_value.replace("\n", ",").split(","):
                name = name.strip().lower().lstrip("*.")
                if "." in name:
                    domains.add(name)
            issuer = cert.get("issuer_name","")
            if issuer:
                issuers.add(issuer)

        return {
            "org":          org_name,
            "total_certs":  len(certs),
            "domains_found":sorted(domains)[:50],
            "issuers":      list(issuers)[:10],
            "certs_sample": certs[:10],
        }

    # ──────────────────────────────────────────────────────────
    # SUSPICIOUS CERT DETECTION
    # ──────────────────────────────────────────────────────────
    def find_suspicious_certs(self, domain: str) -> Dict:
        """
        Find certificates for lookalike/typosquat domains that could
        be used for phishing.
        """
        base = clean_domain(domain).split(".")[0]
        tld  = "." + ".".join(clean_domain(domain).split(".")[1:])

        # Common typosquats
        typosquats = self._generate_typosquats(base, tld)
        found_suspicious = []

        for typo in typosquats[:30]:  # rate limit — check top 30
            resp = safe_request(CRT_SH_API,
                                params={"q": typo, "output": "json"})
            if resp and resp.status_code == 200:
                try:
                    certs = resp.json()
                    if certs:
                        found_suspicious.append({
                            "domain":     typo,
                            "cert_count": len(certs),
                            "latest":     certs[0].get("not_before") if certs else None,
                            "issuer":     certs[0].get("issuer_name","")[:60] if certs else None,
                        })
                except Exception:
                    pass

        return {
            "original_domain":  domain,
            "typosquats_checked": len(typosquats[:30]),
            "suspicious_found": found_suspicious,
            "risk_level":      "HIGH" if found_suspicious else "LOW",
        }

    def _generate_typosquats(self, base: str, tld: str) -> List[str]:
        """Generate common typosquat permutations."""
        squats = []
        # Character substitutions
        subs = {"a":"@4","e":"3","i":"1!","o":"0","s":"5$","t":"7"}
        for i, c in enumerate(base):
            if c.lower() in subs:
                for sub in subs[c.lower()]:
                    squats.append(base[:i] + sub + base[i+1:] + tld)
        # Homograph attacks
        squats.extend([
            f"{base}-verify{tld}", f"{base}-secure{tld}", f"{base}-login{tld}",
            f"{base}-account{tld}", f"secure-{base}{tld}", f"login-{base}{tld}",
            f"{base}verify{tld}", f"{base}login{tld}", f"{base}app{tld}",
        ])
        # Common TLD swaps
        for alt_tld in [".net", ".org", ".co", ".io", ".app", ".live"]:
            if alt_tld != tld:
                squats.append(base + alt_tld)
        return list(set(squats))

    # ──────────────────────────────────────────────────────────
    # CERTIFICATE TIMELINE
    # ──────────────────────────────────────────────────────────
    def certificate_timeline(self, domain: str) -> Dict:
        """Build a timeline showing when certificates were first issued."""
        data   = self.crtsh_search(domain)
        certs  = data.get("latest_certs", [])

        # Group by year
        by_year: Dict[str,int] = {}
        for c in certs:
            ts = c.get("logged_at","") or c.get("not_before","")
            yr = ts[:4] if ts else "unknown"
            by_year[yr] = by_year.get(yr, 0) + 1

        return {
            "domain":       domain,
            "total_certs":  data.get("total_certs"),
            "by_year":      by_year,
            "subdomains":   data.get("subdomains", []),
            "first_cert":   data.get("first_cert"),
            "newest_cert":  data.get("newest_cert"),
            "wildcards":    len(data.get("wildcard_certs", [])),
        }

    # ──────────────────────────────────────────────────────────
    # FULL REPORT
    # ──────────────────────────────────────────────────────────
    def full_report(self, domain: str) -> Dict:
        return {
            "domain":      domain,
            "crtsh":       self.crtsh_search(domain),
            "timeline":    self.certificate_timeline(domain),
            "suspicious":  self.find_suspicious_certs(domain),
        }
