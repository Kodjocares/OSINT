"""
modules/darkweb_intel.py — Dark web OSINT
Search Ahmia (Tor search), ransomware leak trackers, dark paste sites
Works with or without Tor — public clearnet mirrors used when available
"""

import re
import logging
from typing import Dict, List
from bs4 import BeautifulSoup
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

# Clearnet-accessible dark web search indexes
AHMIA_CLEAR = "https://ahmia.fi"

# Ransomware group leak site trackers (clearnet monitoring services)
RANSOMWATCH  = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RANSOMWARE_LIVE = "https://api.ransomware.live/v1/recentvictims"

# Dark web paste mirrors (clearnet)
DARKWEB_PASTES = [
    "https://psbdmp.ws/api/search/",     # Pastebin dump search
]


class DarkWebIntel:
    """
    Dark web intelligence — search Ahmia, ransomware trackers,
    dark paste monitors. Works over clearnet; Tor optional for .onion access.
    """

    def __init__(self, use_tor: bool = False,
                 tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self.use_tor   = use_tor
        self.tor_proxy = tor_proxy
        self.proxies   = {"http": tor_proxy, "https": tor_proxy} if use_tor else None

    def _req(self, url: str, **kwargs) -> object:
        """Request routing: Tor if enabled, else direct."""
        if self.use_tor and self.proxies:
            import requests
            try:
                return requests.get(url, proxies=self.proxies, timeout=30, **kwargs)
            except Exception as e:
                logger.debug(f"[TOR] Failed {url}: {e}")
        return safe_request(url, **kwargs)

    # ──────────────────────────────────────────────────────────
    # AHMIA SEARCH
    # ──────────────────────────────────────────────────────────
    def ahmia_search(self, query: str, pages: int = 2) -> Dict:
        """Search Ahmia.fi Tor search engine (clearnet accessible)."""
        results = []
        for page in range(pages):
            url  = f"{AHMIA_CLEAR}/search/?q={query}&page={page}"
            resp = self._req(url)
            if not resp or resp.status_code != 200:
                break

            soup = BeautifulSoup(resp.text, "lxml")
            for item in soup.find_all("li", class_="result"):
                title = item.find("a")
                desc  = item.find("p")
                onion = item.find("cite")
                if title:
                    results.append({
                        "title":    title.get_text(strip=True),
                        "url":      title.get("href",""),
                        "onion":    onion.get_text(strip=True) if onion else "",
                        "snippet":  desc.get_text(strip=True) if desc else "",
                        "page":     page + 1,
                    })

        return {
            "query":   query,
            "engine":  "ahmia.fi",
            "results": results,
            "count":   len(results),
            "tor_used":self.use_tor,
        }

    # ──────────────────────────────────────────────────────────
    # RANSOMWARE LEAK TRACKER
    # ──────────────────────────────────────────────────────────
    def ransomware_leak_search(self, target: str) -> Dict:
        """
        Search ransomware group leak posts for a target domain/company.
        Uses RansomWatch public dataset (clearnet GitHub).
        """
        result = {
            "target":  target,
            "hits":    [],
            "sources": [],
        }

        # RansomWatch posts.json (public GitHub raw)
        resp = safe_request(RANSOMWATCH)
        if resp and resp.status_code == 200:
            try:
                posts = resp.json()
                target_lower = target.lower()
                for post in posts:
                    title = (post.get("post_title") or "").lower()
                    body  = (post.get("description") or "").lower()
                    if target_lower in title or target_lower in body:
                        result["hits"].append({
                            "source":     "ransomwatch",
                            "group":      post.get("group_name"),
                            "title":      post.get("post_title"),
                            "discovered": post.get("discovered"),
                            "description":post.get("description","")[:300],
                            "screenshot": post.get("screenshot"),
                        })
                result["sources"].append("ransomwatch (github.com/joshhighet/ransomwatch)")
            except Exception as e:
                logger.warning(f"[DARKWEB] RansomWatch parse error: {e}")

        # Ransomware.live API
        resp2 = safe_request(RANSOMWARE_LIVE)
        if resp2 and resp2.status_code == 200:
            try:
                victims = resp2.json()
                target_lower = target.lower()
                for v in (victims if isinstance(victims, list) else []):
                    name   = (v.get("victim") or v.get("company") or "").lower()
                    domain = (v.get("website") or "").lower()
                    if target_lower in name or target_lower in domain:
                        result["hits"].append({
                            "source":      "ransomware.live",
                            "group":       v.get("group"),
                            "victim":      v.get("victim"),
                            "website":     v.get("website"),
                            "discovered":  v.get("discovered"),
                            "description": v.get("description","")[:300],
                        })
                result["sources"].append("ransomware.live API")
            except Exception as e:
                logger.warning(f"[DARKWEB] ransomware.live parse error: {e}")

        result["total_hits"] = len(result["hits"])
        result["risk_level"] = "CRITICAL" if result["hits"] else "NONE"
        return result

    # ──────────────────────────────────────────────────────────
    # DARK PASTE SEARCH
    # ──────────────────────────────────────────────────────────
    def dark_paste_search(self, query: str) -> Dict:
        """Search known dark web paste dump indexes."""
        results = []

        # psbdmp.ws (Pastebin scraper dump, clearnet)
        resp = safe_request(f"https://psbdmp.ws/api/search/{query}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for item in (data.get("data") or [])[:10]:
                    results.append({
                        "source":  "psbdmp",
                        "id":      item.get("id"),
                        "tags":    item.get("tags",""),
                        "url":     f"https://pastebin.com/{item.get('id','')}",
                        "raw":     f"https://pastebin.com/raw/{item.get('id','')}",
                    })
            except Exception:
                pass

        # DDG search for dark paste mentions
        ddg_resp = safe_request(
            f"https://html.duckduckgo.com/html/?q={query}+site:riseup.net+OR+site:paste.i2p2.de"
        )
        if ddg_resp and ddg_resp.status_code == 200:
            soup = BeautifulSoup(ddg_resp.text, "lxml")
            for item in soup.find_all("div", class_="result")[:5]:
                a = item.find("a", class_="result__a")
                if a:
                    results.append({
                        "source":  "ddg_darkpaste",
                        "title":   a.get_text(strip=True),
                        "url":     a.get("href",""),
                    })

        return {"query": query, "results": results, "count": len(results)}

    # ──────────────────────────────────────────────────────────
    # ONION SITE CHECK (Tor required for .onion)
    # ──────────────────────────────────────────────────────────
    def check_onion_site(self, onion_url: str) -> Dict:
        """Check if a .onion site is up (requires Tor)."""
        if not self.use_tor:
            return {
                "url":   onion_url,
                "note":  "Tor not enabled. Set USE_TOR=true in .env to access .onion sites.",
                "reachable": None,
            }
        resp = self._req(onion_url)
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            return {
                "url":       onion_url,
                "reachable": True,
                "title":     soup.title.string.strip() if soup.title else None,
                "size_bytes":len(resp.content),
                "links":     [a["href"] for a in soup.find_all("a", href=True)
                              if a["href"].startswith("http")][:20],
            }
        return {"url": onion_url, "reachable": False}

    # ──────────────────────────────────────────────────────────
    # FULL DARK WEB PROFILE
    # ──────────────────────────────────────────────────────────
    def full_profile(self, target: str) -> Dict:
        """Complete dark web exposure check for a target."""
        return {
            "target":         target,
            "ahmia_search":   self.ahmia_search(target),
            "ransomware_leaks": self.ransomware_leak_search(target),
            "dark_pastes":    self.dark_paste_search(target),
            "tor_enabled":    self.use_tor,
        }
