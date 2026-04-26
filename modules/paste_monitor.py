"""
modules/paste_monitor.py — Paste site search and monitoring
Search Pastebin, GitHub Gists, and other paste sites for target data
"""

import re
import logging
from typing import Dict, List
from bs4 import BeautifulSoup
from utils.helpers import safe_request

logger = logging.getLogger(__name__)


class PasteMonitor:
    """Search paste sites for leaked credentials, personal data, and mentions."""

    # ──────────────────────────────────────────────────────────
    # PASTEBIN SCRAPING (public pastes only)
    # ──────────────────────────────────────────────────────────
    def search_pastebin(self, query: str) -> Dict:
        """Search Pastebin public archive via Google dork."""
        results = []
        search_url = f"https://html.duckduckgo.com/html/?q=site:pastebin.com+{query}"
        resp = safe_request(search_url)
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for item in soup.find_all("div", class_="result"):
                title_tag = item.find("a", class_="result__a")
                snippet   = item.find("a", class_="result__snippet")
                if title_tag:
                    href = title_tag.get("href", "")
                    results.append({
                        "title":   title_tag.get_text(strip=True),
                        "url":     href,
                        "snippet": snippet.get_text(strip=True) if snippet else "",
                        "source":  "pastebin.com",
                    })
        return {"query": query, "results": results, "count": len(results)}

    # ──────────────────────────────────────────────────────────
    # FETCH & ANALYZE PASTE CONTENT
    # ──────────────────────────────────────────────────────────
    def analyze_paste(self, paste_url: str) -> Dict:
        """Download a paste and extract intelligence from its content."""
        # Convert to raw URL if needed
        raw_url = paste_url
        if "pastebin.com" in paste_url and "/raw/" not in paste_url:
            paste_id = paste_url.rstrip("/").split("/")[-1]
            raw_url  = f"https://pastebin.com/raw/{paste_id}"

        resp = safe_request(raw_url)
        if not resp or resp.status_code != 200:
            return {"url": paste_url, "error": "Could not fetch paste"}

        content = resp.text
        return self._extract_intelligence(content, paste_url)

    def _extract_intelligence(self, content: str, source_url: str = "") -> Dict:
        """Run all extraction patterns on paste content."""
        emails   = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", content)))
        ips      = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
        urls     = list(set(re.findall(r"https?://[^\s\"'<>]+", content)))[:20]
        phones   = list(set(re.findall(r"[\+]?\d[\d\s\-\(\)]{7,}\d", content)))[:10]
        hashes   = {
            "md5":    list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", content)))[:5],
            "sha1":   list(set(re.findall(r"\b[a-fA-F0-9]{40}\b", content)))[:5],
            "sha256": list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", content)))[:5],
            "bcrypt": list(set(re.findall(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}", content)))[:5],
        }
        credit_cards = list(set(re.findall(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", content
        )))[:5]
        # Credential patterns (user:pass or email:pass)
        credentials = list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:[^\s\"']{4,}", content
        )))[:20]

        # Classify the paste type
        paste_type = "unknown"
        content_lower = content.lower()
        if credentials or ("password" in content_lower and emails):
            paste_type = "credential_dump"
        elif hashes["md5"] or hashes["sha1"] or hashes["bcrypt"]:
            paste_type = "hash_dump"
        elif credit_cards:
            paste_type = "financial_data"
        elif len(emails) > 10:
            paste_type = "email_list"
        elif len(ips) > 5:
            paste_type = "ip_list"

        return {
            "source_url":   source_url,
            "paste_type":   paste_type,
            "line_count":   len(content.splitlines()),
            "char_count":   len(content),
            "emails":       emails[:30],
            "ips":          ips[:20],
            "urls":         urls,
            "phones":       phones,
            "hashes":       hashes,
            "credit_cards": credit_cards,
            "credentials":  credentials,
            "preview":      content[:300],
        }

    # ──────────────────────────────────────────────────────────
    # MULTI-SOURCE SEARCH
    # ──────────────────────────────────────────────────────────
    def search_all(self, query: str) -> Dict:
        """Search multiple paste and code-sharing sites."""
        sources = {
            "pastebin":   f"site:pastebin.com {query}",
            "ghostbin":   f"site:ghostbin.com {query}",
            "hastebin":   f"site:hastebin.com {query}",
            "gist":       f"site:gist.github.com {query}",
            "rentry":     f"site:rentry.co {query}",
            "controlc":   f"site:controlc.com {query}",
        }
        all_results = []
        for source, dork in sources.items():
            search_url = f"https://html.duckduckgo.com/html/?q={dork}"
            resp = safe_request(search_url)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "lxml")
                for item in soup.find_all("div", class_="result")[:5]:
                    title_tag = item.find("a", class_="result__a")
                    snippet   = item.find("a", class_="result__snippet")
                    if title_tag:
                        all_results.append({
                            "source":  source,
                            "title":   title_tag.get_text(strip=True),
                            "url":     title_tag.get("href", ""),
                            "snippet": snippet.get_text(strip=True) if snippet else "",
                        })

        return {
            "query":   query,
            "total":   len(all_results),
            "results": all_results,
        }
