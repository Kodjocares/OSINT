"""
modules/social_media.py — Public social media profile scraping (no auth required)
"""

import re
import logging
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

class SocialMediaScraper:
    """Scrape publicly available social media profile data."""

    # ─────────────────────────────────────────────
    # GITHUB
    # ─────────────────────────────────────────────
    def scrape_github(self, username: str) -> Dict:
        result = {"platform": "GitHub", "username": username, "profile": {}, "repos": [], "orgs": []}

        # Public API — no key needed for basic data
        api_base = "https://api.github.com"
        profile_resp = safe_request(f"{api_base}/users/{username}")
        if profile_resp and profile_resp.status_code == 200:
            d = profile_resp.json()
            result["profile"] = {
                "name":          d.get("name"),
                "bio":           d.get("bio"),
                "company":       d.get("company"),
                "location":      d.get("location"),
                "email":         d.get("email"),
                "blog":          d.get("blog"),
                "twitter":       d.get("twitter_username"),
                "followers":     d.get("followers"),
                "following":     d.get("following"),
                "public_repos":  d.get("public_repos"),
                "public_gists":  d.get("public_gists"),
                "created_at":    d.get("created_at"),
                "updated_at":    d.get("updated_at"),
                "avatar_url":    d.get("avatar_url"),
            }

        # Repos
        repos_resp = safe_request(f"{api_base}/users/{username}/repos", params={"per_page": 30})
        if repos_resp and repos_resp.status_code == 200:
            result["repos"] = [
                {
                    "name":        r.get("name"),
                    "description": r.get("description"),
                    "language":    r.get("language"),
                    "stars":       r.get("stargazers_count"),
                    "forks":       r.get("forks_count"),
                    "url":         r.get("html_url"),
                    "topics":      r.get("topics", []),
                    "created_at":  r.get("created_at"),
                    "updated_at":  r.get("updated_at"),
                }
                for r in repos_resp.json()
            ]

        # Orgs
        orgs_resp = safe_request(f"{api_base}/users/{username}/orgs")
        if orgs_resp and orgs_resp.status_code == 200:
            result["orgs"] = [o.get("login") for o in orgs_resp.json()]

        # Events (recent activity)
        events_resp = safe_request(f"{api_base}/users/{username}/events/public", params={"per_page": 10})
        if events_resp and events_resp.status_code == 200:
            result["recent_activity"] = [
                {"type": e.get("type"), "repo": e.get("repo", {}).get("name"), "created_at": e.get("created_at")}
                for e in events_resp.json()
            ]

        return result

    # ─────────────────────────────────────────────
    # REDDIT
    # ─────────────────────────────────────────────
    def scrape_reddit(self, username: str) -> Dict:
        result = {"platform": "Reddit", "username": username, "profile": {}, "posts": []}
        api_url = f"https://www.reddit.com/user/{username}/about.json"
        posts_url = f"https://www.reddit.com/user/{username}/submitted.json"

        resp = safe_request(api_url, headers={"Accept": "application/json"})
        if resp and resp.status_code == 200:
            data = resp.json().get("data", {})
            result["profile"] = {
                "name":            data.get("name"),
                "link_karma":      data.get("link_karma"),
                "comment_karma":   data.get("comment_karma"),
                "created_utc":     data.get("created_utc"),
                "is_gold":         data.get("is_gold"),
                "is_mod":          data.get("is_mod"),
                "verified":        data.get("verified"),
                "icon_img":        data.get("icon_img"),
            }

        posts_resp = safe_request(posts_url, headers={"Accept": "application/json"},
                                   params={"limit": 10})
        if posts_resp and posts_resp.status_code == 200:
            children = posts_resp.json().get("data", {}).get("children", [])
            result["posts"] = [
                {
                    "title":      c["data"].get("title"),
                    "subreddit":  c["data"].get("subreddit"),
                    "score":      c["data"].get("score"),
                    "url":        c["data"].get("url"),
                    "created":    c["data"].get("created_utc"),
                }
                for c in children
            ]

        return result

    # ─────────────────────────────────────────────
    # GENERIC PROFILE SCRAPER
    # ─────────────────────────────────────────────
    def scrape_generic_profile(self, url: str, platform: str = "Unknown") -> Dict:
        """
        Scrape a public profile URL for visible text data.
        Returns meta tags, links, emails, and phone numbers found in the page.
        """
        result = {"platform": platform, "url": url, "data": {}}
        resp = safe_request(url)
        if not resp or resp.status_code != 200:
            result["error"] = f"Could not reach {url}"
            return result

        soup = BeautifulSoup(resp.text, "lxml")

        # Meta tags
        metas = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                metas[name] = content
        result["data"]["meta"] = metas

        # Title
        result["data"]["title"] = soup.title.string.strip() if soup.title else None

        # Emails in page
        emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", resp.text)
        result["data"]["emails"] = list(set(emails))

        # Phone numbers
        phones = re.findall(r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{3,4}[-\s\.]?[0-9]{3,4}", resp.text)
        result["data"]["phones"] = list(set(phones))[:10]

        # External links
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http") and url not in href:
                links.add(href)
        result["data"]["external_links"] = list(links)[:20]

        return result

    # ─────────────────────────────────────────────
    # MULTI-PLATFORM SUMMARY
    # ─────────────────────────────────────────────
    def full_social_scan(self, username: str) -> Dict:
        results = {
            "username": username,
            "github":  self.scrape_github(username),
            "reddit":  self.scrape_reddit(username),
        }
        return results
