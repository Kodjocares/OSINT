"""
modules/network_intel.py — ASN, BGP, and network range intelligence
Map IP blocks, identify hosting providers, trace network ownership
"""

import socket
import logging
from typing import Dict, List, Optional
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

BGP_HE_API  = "https://bgp.he.net"
IPINFO_API  = "https://ipinfo.io"
RDAP_API    = "https://rdap.arin.net/registry"
BGPVIEW_API = "https://api.bgpview.io"


class NetworkIntel:
    """ASN, BGP routing, and IP network block intelligence."""

    def __init__(self, ipinfo_token: str = ""):
        self.ipinfo_token = ipinfo_token

    # ──────────────────────────────────────────────────────────
    # ASN LOOKUP
    # ──────────────────────────────────────────────────────────
    def asn_lookup(self, asn: str) -> Dict:
        """Get full details about an Autonomous System Number."""
        # Strip 'AS' prefix if present
        asn_num = asn.upper().lstrip("AS")
        result = {"asn": f"AS{asn_num}", "info": {}, "prefixes_v4": [],
                  "prefixes_v6": [], "peers": [], "upstreams": [], "ix_info": []}

        # BGPView (free, no key)
        resp = safe_request(f"{BGPVIEW_API}/asn/{asn_num}")
        if resp and resp.status_code == 200:
            d = resp.json().get("data", {})
            result["info"] = {
                "name":           d.get("name"),
                "description":    d.get("description_short"),
                "country":        d.get("country_code"),
                "rir":            d.get("rir_allocation", {}).get("rir_name"),
                "date_allocated": d.get("rir_allocation", {}).get("date_allocated"),
                "website":        d.get("website"),
                "email_contacts": d.get("email_contacts", []),
                "abuse_contacts": d.get("abuse_contacts", []),
            }

        # Prefixes (IP ranges)
        pfx_resp = safe_request(f"{BGPVIEW_API}/asn/{asn_num}/prefixes")
        if pfx_resp and pfx_resp.status_code == 200:
            d = pfx_resp.json().get("data", {})
            result["prefixes_v4"] = [
                {"prefix": p.get("prefix"), "name": p.get("name"),
                 "description": p.get("description"), "country": p.get("country_code")}
                for p in d.get("ipv4_prefixes", [])[:20]
            ]
            result["prefixes_v6"] = [
                {"prefix": p.get("prefix"), "name": p.get("name")}
                for p in d.get("ipv6_prefixes", [])[:10]
            ]

        # Peers
        peers_resp = safe_request(f"{BGPVIEW_API}/asn/{asn_num}/peers")
        if peers_resp and peers_resp.status_code == 200:
            d = peers_resp.json().get("data", {})
            result["peers"] = [
                {"asn": p.get("asn"), "name": p.get("name"), "country": p.get("country_code")}
                for p in d.get("ipv4_peers", [])[:15]
            ]

        # Upstreams
        up_resp = safe_request(f"{BGPVIEW_API}/asn/{asn_num}/upstreams")
        if up_resp and up_resp.status_code == 200:
            d = up_resp.json().get("data", {})
            result["upstreams"] = [
                {"asn": u.get("asn"), "name": u.get("name"), "country": u.get("country_code")}
                for u in d.get("ipv4_upstreams", [])[:10]
            ]

        return result

    # ──────────────────────────────────────────────────────────
    # IP TO ASN
    # ──────────────────────────────────────────────────────────
    def ip_to_asn(self, ip: str) -> Dict:
        """Find which ASN owns an IP address."""
        token = f"?token={self.ipinfo_token}" if self.ipinfo_token else ""
        resp  = safe_request(f"{IPINFO_API}/{ip}/json{token}")
        result = {"ip": ip}

        if resp and resp.status_code == 200:
            d = resp.json()
            org = d.get("org", "")
            asn = org.split(" ")[0] if org else None
            result.update({
                "asn":      asn,
                "org":      org,
                "hostname": d.get("hostname"),
                "city":     d.get("city"),
                "region":   d.get("region"),
                "country":  d.get("country"),
                "timezone": d.get("timezone"),
            })

        # BGPView cross-reference
        bgp_resp = safe_request(f"{BGPVIEW_API}/ip/{ip}")
        if bgp_resp and bgp_resp.status_code == 200:
            d = bgp_resp.json().get("data", {})
            prefixes = d.get("prefixes", [])
            if prefixes:
                best = prefixes[0]
                asn_info = best.get("asn", {})
                result["bgpview"] = {
                    "prefix": best.get("prefix"),
                    "asn":    asn_info.get("asn"),
                    "name":   asn_info.get("name"),
                    "country":asn_info.get("country_code"),
                }

        return result

    # ──────────────────────────────────────────────────────────
    # ORGANISATION IP RANGES
    # ──────────────────────────────────────────────────────────
    def org_ip_ranges(self, org_name: str) -> Dict:
        """Find all IP ranges registered to an organization name."""
        resp = safe_request(f"{BGPVIEW_API}/search", params={"query_term": org_name})
        results = {"org": org_name, "asns": [], "prefixes": []}

        if resp and resp.status_code == 200:
            data = resp.json().get("data", {})
            for asn in data.get("asns", [])[:10]:
                results["asns"].append({
                    "asn":     asn.get("asn"),
                    "name":    asn.get("name"),
                    "country": asn.get("country_code"),
                })
            for pfx in data.get("ipv4_prefixes", [])[:20]:
                results["prefixes"].append({
                    "prefix":  pfx.get("prefix"),
                    "name":    pfx.get("name"),
                    "country": pfx.get("country_code"),
                })
        return results

    # ──────────────────────────────────────────────────────────
    # RDAP (ARIN / RIPE registration)
    # ──────────────────────────────────────────────────────────
    def rdap_lookup(self, ip: str) -> Dict:
        """Query RDAP for official IP registration data."""
        resp = safe_request(f"{RDAP_API}/ip/{ip}")
        if resp and resp.status_code == 200:
            d = resp.json()
            entities = d.get("entities", [])
            contacts = []
            for e in entities:
                vcard = e.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            contacts.append(field[3])

            return {
                "ip":          ip,
                "name":        d.get("name"),
                "type":        d.get("type"),
                "start_address": d.get("startAddress"),
                "end_address": d.get("endAddress"),
                "country":     d.get("country"),
                "handle":      d.get("handle"),
                "contacts":    contacts,
                "events":      [
                    {"action": e.get("eventAction"), "date": e.get("eventDate")}
                    for e in d.get("events", [])
                ],
            }
        return {"ip": ip, "error": "RDAP lookup failed"}

    # ──────────────────────────────────────────────────────────
    # PORT SCAN (basic, no Shodan)
    # ──────────────────────────────────────────────────────────
    def quick_port_check(self, host: str,
                          ports: List[int] = None) -> Dict:
        """Quick TCP port connectivity check."""
        ports = ports or [21,22,23,25,53,80,110,143,443,445,
                          3306,3389,5432,6379,8080,8443,27017]
        open_ports, closed_ports = [], []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
            except Exception:
                closed_ports.append(port)

        return {
            "host":        host,
            "open_ports":  open_ports,
            "closed_ports":closed_ports,
            "total_checked": len(ports),
        }
