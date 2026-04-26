"""
modules/domain_intel.py — WHOIS, DNS, subdomain enum, SSL, Shodan, VirusTotal
"""

import socket
import logging
from typing import Dict, List, Optional
from utils.helpers import safe_request, clean_domain
from config import SHODAN_API_KEY, VIRUSTOTAL_API_KEY, IPINFO_TOKEN

logger = logging.getLogger(__name__)

class DomainIntel:
    """Full domain & IP intelligence gathering."""

    # ─────────────────────────────────────────────
    # WHOIS
    # ─────────────────────────────────────────────
    def whois_lookup(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        try:
            import whois
            w = whois.whois(domain)
            return {
                "domain":         domain,
                "registrar":      w.registrar,
                "creation_date":  str(w.creation_date),
                "expiration_date":str(w.expiration_date),
                "updated_date":   str(w.updated_date),
                "name_servers":   w.name_servers,
                "status":         w.status,
                "emails":         w.emails,
                "registrant":     w.org or w.name,
                "country":        w.country,
                "dnssec":         w.dnssec,
            }
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    # ─────────────────────────────────────────────
    # DNS ENUMERATION
    # ─────────────────────────────────────────────
    def dns_lookup(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"]
        records = {}
        try:
            import dns.resolver
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
        except ImportError:
            records["error"] = "dnspython not installed"
        return {"domain": domain, "records": records}

    # ─────────────────────────────────────────────
    # SUBDOMAIN ENUMERATION
    # ─────────────────────────────────────────────
    def enumerate_subdomains(self, domain: str,
                              wordlist: Optional[List[str]] = None) -> Dict:
        domain = clean_domain(domain)
        found = []
        default_subs = [
            "www","mail","ftp","smtp","pop","imap","admin","portal","vpn",
            "api","dev","staging","test","beta","app","cdn","blog","shop",
            "support","help","docs","git","ns1","ns2","mx","webmail","cpanel",
            "dashboard","login","auth","remote","mobile","static","assets",
        ]
        subs_to_check = wordlist or default_subs

        # Certificate Transparency via crt.sh
        ct_results = self._crtsh_subdomains(domain)
        found.extend(ct_results)

        # DNS brute-force
        for sub in subs_to_check:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                if fqdn not in found:
                    found.append(fqdn)
            except socket.gaierror:
                pass

        return {"domain": domain, "subdomains": list(set(found)), "count": len(set(found))}

    def _crtsh_subdomains(self, domain: str) -> List[str]:
        """Certificate Transparency log search for subdomains."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = safe_request(url)
        if not resp:
            return []
        try:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        subs.add(line)
            return list(subs)
        except Exception:
            return []

    # ─────────────────────────────────────────────
    # SSL / TLS CERTIFICATE
    # ─────────────────────────────────────────────
    def ssl_certificate_info(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        try:
            import ssl
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                return {
                    "domain":       domain,
                    "subject":      dict(x[0] for x in cert.get("subject", [])),
                    "issuer":       dict(x[0] for x in cert.get("issuer", [])),
                    "valid_from":   cert.get("notBefore"),
                    "valid_until":  cert.get("notAfter"),
                    "san":          cert.get("subjectAltName", []),
                    "serial":       cert.get("serialNumber"),
                    "version":      cert.get("version"),
                }
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    # ─────────────────────────────────────────────
    # IP INTELLIGENCE
    # ─────────────────────────────────────────────
    def ip_lookup(self, ip: str) -> Dict:
        result = {"ip": ip, "ipinfo": {}, "shodan": {}, "virustotal": {}, "reverse_dns": []}

        # IPInfo
        token_param = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
        resp = safe_request(f"https://ipinfo.io/{ip}/json{token_param}")
        if resp and resp.status_code == 200:
            result["ipinfo"] = resp.json()

        # Reverse DNS
        try:
            result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result["reverse_dns"] = "No PTR record"

        # Shodan
        if SHODAN_API_KEY:
            result["shodan"] = self._shodan_lookup(ip)

        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            result["virustotal"] = self._virustotal_ip(ip)

        return result

    def _shodan_lookup(self, ip: str) -> Dict:
        resp = safe_request(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY}
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            return {
                "open_ports": data.get("ports", []),
                "hostnames":  data.get("hostnames", []),
                "org":        data.get("org"),
                "os":         data.get("os"),
                "vulns":      list(data.get("vulns", {}).keys()),
                "tags":       data.get("tags", []),
                "services":   [
                    {"port": s.get("port"), "product": s.get("product"), "version": s.get("version")}
                    for s in data.get("data", [])
                ],
            }
        return {}

    def _virustotal_ip(self, ip: str) -> Dict:
        resp = safe_request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "reputation": attrs.get("reputation", 0),
                "country":    attrs.get("country"),
                "asn":        attrs.get("asn"),
            }
        return {}

    # ─────────────────────────────────────────────
    # TECHNOLOGY STACK FINGERPRINTING
    # ─────────────────────────────────────────────
    def fingerprint_technologies(self, domain: str) -> Dict:
        domain = clean_domain(domain)
        tech = {"domain": domain, "technologies": [], "headers": {}, "cms": None}
        resp = safe_request(f"https://{domain}")
        if not resp:
            resp = safe_request(f"http://{domain}")
        if not resp:
            return tech

        tech["headers"] = dict(resp.headers)
        body = resp.text.lower()

        detections = {
            "WordPress":    ["wp-content", "wp-includes", "wordpress"],
            "Drupal":       ["drupal", "/sites/default/files"],
            "Joomla":       ["joomla", "/components/com_"],
            "React":        ["react", "_next", "__react"],
            "Angular":      ["ng-version", "angular"],
            "Vue.js":       ["vue.js", "__vue"],
            "jQuery":       ["jquery"],
            "Bootstrap":    ["bootstrap"],
            "Nginx":        ["nginx"],
            "Apache":       ["apache"],
            "Cloudflare":   ["cf-ray", "cloudflare"],
            "PHP":          ["x-powered-by: php", ".php"],
            "Python":       ["django", "flask", "wsgi"],
            "Laravel":      ["laravel", "x-powered-by: laravel"],
        }

        for tech_name, signals in detections.items():
            combined = body + str(resp.headers).lower()
            if any(s in combined for s in signals):
                tech["technologies"].append(tech_name)

        return tech
