"""
utils/helpers.py — Shared utilities: HTTP client, rate limiting, user-agent rotation
"""

import time
import random
import requests
import logging
from typing import Optional, Dict, Any
from config import (
    REQUEST_TIMEOUT, REQUEST_DELAY, MAX_RETRIES,
    ROTATE_USER_AGENTS, USE_TOR, TOR_PROXY,
    HTTP_PROXY, HTTPS_PROXY
)

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0",
]

def get_headers() -> Dict[str, str]:
    ua = random.choice(USER_AGENTS) if ROTATE_USER_AGENTS else USER_AGENTS[0]
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": "1",
    }

def get_proxies() -> Optional[Dict[str, str]]:
    if USE_TOR:
        return {"http": TOR_PROXY, "https": TOR_PROXY}
    if HTTP_PROXY or HTTPS_PROXY:
        return {
            "http": HTTP_PROXY or HTTPS_PROXY,
            "https": HTTPS_PROXY or HTTP_PROXY,
        }
    return None

def safe_request(url: str, method: str = "GET", params: dict = None,
                 headers: dict = None, json_data: dict = None,
                 allow_redirects: bool = True) -> Optional[requests.Response]:
    """Rate-limited, retry-aware HTTP request."""
    _headers = get_headers()
    if headers:
        _headers.update(headers)
    proxies = get_proxies()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            time.sleep(REQUEST_DELAY + random.uniform(0, 0.5))
            resp = requests.request(
                method, url,
                headers=_headers,
                params=params,
                json=json_data,
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=allow_redirects,
            )
            return resp
        except requests.exceptions.RequestException as e:
            logger.warning(f"[Attempt {attempt}/{MAX_RETRIES}] Request failed for {url}: {e}")
            time.sleep(attempt * 2)
    return None

def clean_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/")

def save_json(data: Any, filepath: str) -> None:
    import json, os
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

def load_json(filepath: str) -> Any:
    import json
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)
