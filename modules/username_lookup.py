"""
modules/username_lookup.py — Username/Email enumeration across platforms
"""

import re
import logging
import concurrent.futures
from typing import Dict, List
from utils.helpers import safe_request
from config import SOCIAL_PLATFORMS, HUNTER_IO_API_KEY

logger = logging.getLogger(__name__)

class UsernameLookup:
    """Check username presence across dozens of platforms & investigate emails."""

    def __init__(self):
        self.platforms = SOCIAL_PLATFORMS

    # ─────────────────────────────────────────────
    # USERNAME SEARCH
    # ─────────────────────────────────────────────
    def search_username(self, username: str, max_workers: int = 10) -> Dict:
        """Check username across all configured platforms in parallel."""
        results = {"username": username, "found": [], "not_found": [], "errors": []}

        def _check(url_template: str):
            url = url_template.format(username=username)
            try:
                resp = safe_request(url, allow_redirects=True)
                if resp is None:
                    results["errors"].append({"url": url, "reason": "timeout/no response"})
                    return
                platform = url.split("/")[2].replace("www.", "")
                if resp.status_code == 200:
                    # Basic content check — avoid false positives
                    body = resp.text.lower()
                    false_pos_signals = [
                        "user not found", "page not found", "doesn't exist",
                        "no user", "profile unavailable", "404",
                    ]
                    if not any(s in body for s in false_pos_signals):
                        results["found"].append({"platform": platform, "url": url, "status": 200})
                    else:
                        results["not_found"].append({"platform": platform, "url": url, "status": "false_positive"})
                elif resp.status_code == 404:
                    results["not_found"].append({"platform": platform, "url": url, "status": 404})
                else:
                    results["errors"].append({"platform": platform, "url": url, "status": resp.status_code})
            except Exception as e:
                results["errors"].append({"url": url_template, "reason": str(e)})

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(_check, self.platforms)

        results["summary"] = {
            "total_checked": len(self.platforms),
            "found_count":   len(results["found"]),
            "not_found":     len(results["not_found"]),
            "errors":        len(results["errors"]),
        }
        return results

    # ─────────────────────────────────────────────
    # EMAIL INVESTIGATION
    # ─────────────────────────────────────────────
    def investigate_email(self, email: str) -> Dict:
        """Validate email format, check MX records, and query Hunter.io."""
        result = {
            "email": email,
            "valid_format": False,
            "domain": None,
            "mx_records": [],
            "hunter_io": {},
            "gravatar": None,
        }

        # Validate format
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            result["error"] = "Invalid email format"
            return result
        result["valid_format"] = True

        # Extract domain
        domain = email.split("@")[1]
        result["domain"] = domain

        # MX records
        result["mx_records"] = self._get_mx_records(domain)

        # Hunter.io lookup
        if HUNTER_IO_API_KEY:
            result["hunter_io"] = self._hunter_lookup(email)

        # Gravatar MD5 hash check
        result["gravatar"] = self._check_gravatar(email)

        return result

    def _get_mx_records(self, domain: str) -> List[str]:
        try:
            import dns.resolver
            mx = dns.resolver.resolve(domain, "MX")
            return [str(r.exchange) for r in mx]
        except Exception:
            return []

    def _hunter_lookup(self, email: str) -> Dict:
        url = "https://api.hunter.io/v2/email-verifier"
        resp = safe_request(url, params={"email": email, "api_key": HUNTER_IO_API_KEY})
        if resp and resp.status_code == 200:
            return resp.json().get("data", {})
        return {}

    def _check_gravatar(self, email: str) -> str:
        import hashlib
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        resp = safe_request(url)
        if resp and resp.status_code == 200:
            return f"https://www.gravatar.com/avatar/{h}"
        return "No Gravatar found"
