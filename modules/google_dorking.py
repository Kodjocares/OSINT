"""
modules/google_dorking.py — Automated Google dork query generation and execution
"""

import time
import logging
import urllib.parse
from typing import Dict, List, Optional
from utils.helpers import safe_request
from config import DORK_TEMPLATES, GOOGLE_API_KEY, GOOGLE_CSE_ID

logger = logging.getLogger(__name__)

class GoogleDorking:
    """Generate and execute Google dork queries for OSINT reconnaissance."""

    GOOGLE_SEARCH_URL = "https://www.google.com/search"
    GOOGLE_API_URL    = "https://www.googleapis.com/customsearch/v1"

    # ─────────────────────────────────────────────
    # DORK GENERATION
    # ─────────────────────────────────────────────
    def generate_dorks(self, target: str, query: str = "", 
                       categories: Optional[List[str]] = None) -> Dict:
        """Generate dork queries for a target domain/entity."""
        cats = categories or list(DORK_TEMPLATES.keys())
        dorks = {}
        for cat in cats:
            if cat in DORK_TEMPLATES:
                template = DORK_TEMPLATES[cat]
                dork = template.format(target=target, query=query or target)
                dorks[cat] = {
                    "query":       dork,
                    "google_url":  f"https://www.google.com/search?q={urllib.parse.quote(dork)}",
                    "duckduckgo":  f"https://duckduckgo.com/?q={urllib.parse.quote(dork)}",
                    "bing_url":    f"https://www.bing.com/search?q={urllib.parse.quote(dork)}",
                }
        return {"target": target, "dorks": dorks, "total": len(dorks)}

    # ─────────────────────────────────────────────
    # CUSTOM DORK BUILDER
    # ─────────────────────────────────────────────
    def build_custom_dork(self,
                          site: str = None,
                          inurl: str = None,
                          intitle: str = None,
                          intext: str = None,
                          filetype: str = None,
                          keywords: str = None,
                          exclude: List[str] = None) -> str:
        """Build a custom Google dork from individual operators."""
        parts = []
        if site:     parts.append(f"site:{site}")
        if inurl:    parts.append(f"inurl:{inurl}")
        if intitle:  parts.append(f'intitle:"{intitle}"')
        if intext:   parts.append(f'intext:"{intext}"')
        if filetype: parts.append(f"filetype:{filetype}")
        if keywords: parts.append(keywords)
        if exclude:
            for term in exclude:
                parts.append(f"-{term}")
        return " ".join(parts)

    # ─────────────────────────────────────────────
    # EXECUTE VIA GOOGLE API
    # ─────────────────────────────────────────────
    def search_via_api(self, query: str, num_results: int = 10) -> Dict:
        """Execute a dork search using Google Custom Search API."""
        if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
            return {
                "error": "Google API key or CSE ID not configured",
                "manual_url": f"https://www.google.com/search?q={urllib.parse.quote(query)}",
                "query": query,
            }

        results_list = []
        start = 1
        while len(results_list) < num_results:
            resp = safe_request(
                self.GOOGLE_API_URL,
                params={
                    "key":   GOOGLE_API_KEY,
                    "cx":    GOOGLE_CSE_ID,
                    "q":     query,
                    "num":   min(10, num_results - len(results_list)),
                    "start": start,
                }
            )
            if not resp or resp.status_code != 200:
                break
            data = resp.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                results_list.append({
                    "title":   item.get("title"),
                    "url":     item.get("link"),
                    "snippet": item.get("snippet"),
                    "domain":  urllib.parse.urlparse(item.get("link", "")).netloc,
                })
            start += 10
            if start > 91:
                break
            time.sleep(1)

        return {
            "query":        query,
            "result_count": len(results_list),
            "results":      results_list,
        }

    # ─────────────────────────────────────────────
    # EXECUTE VIA WEB SCRAPING (fallback)
    # ─────────────────────────────────────────────
    def search_scrape(self, query: str, engine: str = "duckduckgo") -> Dict:
        """Scrape search results from DuckDuckGo (more scraping-friendly)."""
        from bs4 import BeautifulSoup

        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        resp = safe_request(url)
        if not resp or resp.status_code != 200:
            return {"error": "Search failed", "query": query}

        soup = BeautifulSoup(resp.text, "lxml")
        results = []

        for result in soup.find_all("div", class_="result"):
            title_tag = result.find("a", class_="result__a")
            snippet_tag = result.find("a", class_="result__snippet")
            if title_tag:
                link = title_tag.get("href", "")
                results.append({
                    "title":   title_tag.get_text(strip=True),
                    "url":     link,
                    "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                    "domain":  urllib.parse.urlparse(link).netloc,
                })

        return {"query": query, "engine": engine, "result_count": len(results), "results": results}

    # ─────────────────────────────────────────────
    # FULL DORK CAMPAIGN
    # ─────────────────────────────────────────────
    def run_dork_campaign(self, target: str, use_api: bool = False,
                          categories: Optional[List[str]] = None) -> Dict:
        """Generate and optionally execute a full dork campaign for a target."""
        dork_data = self.generate_dorks(target, categories=categories)
        campaign_results = {"target": target, "dorks_run": [], "all_results": []}

        for cat, dork_info in dork_data["dorks"].items():
            query = dork_info["query"]
            logger.info(f"[DORK] Running: {cat} — {query}")

            if use_api and GOOGLE_API_KEY:
                search_result = self.search_via_api(query, num_results=5)
            else:
                search_result = self.search_scrape(query)

            dork_run = {
                "category": cat,
                "query":    query,
                "urls":     dork_info,
                "results":  search_result.get("results", []),
                "count":    search_result.get("result_count", 0),
            }
            campaign_results["dorks_run"].append(dork_run)
            campaign_results["all_results"].extend(search_result.get("results", []))
            time.sleep(2)

        campaign_results["total_findings"] = len(campaign_results["all_results"])
        return campaign_results
