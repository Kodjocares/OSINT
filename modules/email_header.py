"""
modules/email_header.py — Email header forensics
Parse raw email headers to trace origin, detect spoofing, geolocate senders
"""

import re
import logging
from email import message_from_string
from email.header import decode_header
from typing import Dict, List, Optional
from utils.helpers import safe_request

logger = logging.getLogger(__name__)


class EmailHeaderAnalyzer:
    """Parse and analyze raw email headers for OSINT and fraud investigation."""

    # ──────────────────────────────────────────────────────────
    # MAIN ANALYSIS
    # ──────────────────────────────────────────────────────────
    def analyze(self, raw_headers: str) -> Dict:
        """Full analysis of a raw email header block."""
        result = {
            "sender":        {},
            "recipients":    [],
            "routing":       [],
            "authentication":{},
            "timestamps":    [],
            "ips_found":     [],
            "geolocations":  [],
            "spoofing_indicators": [],
            "risk_score":    0,
            "summary":       "",
        }

        msg = message_from_string(raw_headers)

        # Basic fields
        result["sender"] = {
            "from":       self._decode_header_value(msg.get("From", "")),
            "reply_to":   self._decode_header_value(msg.get("Reply-To", "")),
            "return_path":self._decode_header_value(msg.get("Return-Path", "")),
            "sender":     self._decode_header_value(msg.get("Sender", "")),
        }

        result["recipients"] = {
            "to":  self._decode_header_value(msg.get("To", "")),
            "cc":  self._decode_header_value(msg.get("Cc", "")),
            "bcc": self._decode_header_value(msg.get("Bcc", "")),
        }

        result["subject"]    = self._decode_header_value(msg.get("Subject", ""))
        result["date"]       = msg.get("Date", "")
        result["message_id"] = msg.get("Message-ID", "")
        result["mailer"]     = msg.get("X-Mailer") or msg.get("User-Agent", "")

        # Parse Received headers (hop chain)
        result["routing"] = self._parse_received_headers(raw_headers)

        # Extract all IPs from headers
        all_ips = self._extract_ips(raw_headers)
        # Filter out private IPs
        public_ips = [ip for ip in all_ips if not self._is_private_ip(ip)]
        result["ips_found"] = public_ips

        # Geolocate public IPs
        for ip in public_ips[:5]:
            geo = self._geolocate_ip(ip)
            if geo:
                result["geolocations"].append(geo)

        # SPF / DKIM / DMARC
        result["authentication"] = {
            "spf":        self._extract_auth_result(raw_headers, "spf"),
            "dkim":       self._extract_auth_result(raw_headers, "dkim"),
            "dmarc":      self._extract_auth_result(raw_headers, "dmarc"),
            "auth_results": msg.get("Authentication-Results", ""),
            "received_spf": msg.get("Received-SPF", ""),
            "dkim_signature": "present" if msg.get("DKIM-Signature") else "absent",
        }

        # Spoofing detection
        result["spoofing_indicators"] = self._detect_spoofing(result, raw_headers)
        result["risk_score"] = len(result["spoofing_indicators"]) * 20

        # Summary
        from_addr  = result["sender"].get("from", "unknown")
        hop_count  = len(result["routing"])
        auth_pass  = result["authentication"].get("spf", "").lower()
        spoof_flag = " ⚠ SPOOFING INDICATORS DETECTED" if result["spoofing_indicators"] else ""
        result["summary"] = (f"From: {from_addr} | Hops: {hop_count} | "
                             f"SPF: {auth_pass} | IPs: {len(public_ips)}{spoof_flag}")
        return result

    # ──────────────────────────────────────────────────────────
    # PARSE RECEIVED HEADERS
    # ──────────────────────────────────────────────────────────
    def _parse_received_headers(self, raw: str) -> List[Dict]:
        hops = []
        received_blocks = re.findall(
            r"Received:\s*(.*?)(?=\nReceived:|\nFrom:|\nTo:|\Z)",
            raw, re.DOTALL | re.IGNORECASE
        )
        for i, block in enumerate(received_blocks):
            block = block.strip().replace("\n", " ").replace("\t", " ")
            # Extract IP
            ips = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", block)
            # Extract hostname
            hostnames = re.findall(r"from\s+([a-zA-Z0-9\-\.]+)\s", block, re.IGNORECASE)
            # Extract timestamp
            timestamps = re.findall(
                r";\s*([A-Z][a-z]{2},\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+[\d:]+\s+[+-]\d{4})",
                block
            )
            hops.append({
                "hop":       i + 1,
                "raw":       block[:200],
                "ips":       ips,
                "hostnames": hostnames[:3],
                "timestamp": timestamps[0] if timestamps else None,
                "by":        re.search(r"by\s+([a-zA-Z0-9\-\.]+)\s", block, re.I).group(1)
                             if re.search(r"by\s+([a-zA-Z0-9\-\.]+)\s", block, re.I) else None,
            })
        return hops

    # ──────────────────────────────────────────────────────────
    # SPOOFING DETECTION
    # ──────────────────────────────────────────────────────────
    def _detect_spoofing(self, result: Dict, raw: str) -> List[str]:
        indicators = []

        # From vs Return-Path mismatch
        from_domain = self._extract_domain(result["sender"].get("from", ""))
        rp_domain   = self._extract_domain(result["sender"].get("return_path", ""))
        if from_domain and rp_domain and from_domain != rp_domain:
            indicators.append(f"From domain ({from_domain}) != Return-Path domain ({rp_domain})")

        # From vs Reply-To mismatch
        rt_domain = self._extract_domain(result["sender"].get("reply_to", ""))
        if from_domain and rt_domain and from_domain != rt_domain:
            indicators.append(f"From domain ({from_domain}) != Reply-To domain ({rt_domain})")

        # SPF fail
        spf = result["authentication"].get("spf", "").lower()
        if "fail" in spf or "softfail" in spf:
            indicators.append(f"SPF check: {spf}")

        # DKIM absent
        if result["authentication"].get("dkim_signature") == "absent":
            indicators.append("No DKIM signature present")

        # DMARC fail
        dmarc = result["authentication"].get("dmarc", "").lower()
        if "fail" in dmarc:
            indicators.append(f"DMARC check: {dmarc}")

        # Suspicious mailer
        mailer = (result.get("mailer") or "").lower()
        if any(s in mailer for s in ["bulk", "mass", "phpmailer", "sendblaster"]):
            indicators.append(f"Suspicious mailer: {result.get('mailer')}")

        return indicators

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────
    def _extract_ips(self, text: str) -> List[str]:
        return list(set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)))

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            p = [int(x) for x in parts]
            return (p[0] == 10 or p[0] == 127 or
                    (p[0] == 172 and 16 <= p[1] <= 31) or
                    (p[0] == 192 and p[1] == 168))
        except Exception:
            return True

    def _geolocate_ip(self, ip: str) -> Optional[Dict]:
        resp = safe_request(f"http://ip-api.com/json/{ip}")
        if resp and resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                return {"ip": ip, "country": d.get("country"),
                        "city": d.get("city"), "isp": d.get("isp"),
                        "org": d.get("org"), "lat": d.get("lat"), "lon": d.get("lon")}
        return None

    def _extract_auth_result(self, raw: str, auth_type: str) -> str:
        pattern = rf"{auth_type}\s*=\s*([a-zA-Z0-9_\-]+)"
        match = re.search(pattern, raw, re.IGNORECASE)
        return match.group(1) if match else "not_found"

    def _decode_header_value(self, value: str) -> str:
        try:
            decoded = decode_header(value)
            parts = []
            for part, enc in decoded:
                if isinstance(part, bytes):
                    parts.append(part.decode(enc or "utf-8", errors="replace"))
                else:
                    parts.append(str(part))
            return " ".join(parts)
        except Exception:
            return value

    def _extract_domain(self, email_str: str) -> Optional[str]:
        match = re.search(r"@([a-zA-Z0-9.\-]+)", email_str)
        return match.group(1).lower() if match else None
