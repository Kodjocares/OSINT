"""
modules/reverse_image.py — Reverse image search and image intelligence
Google, Yandex, TinEye, Bing via URL submissions + OCR text extraction
"""

import os
import base64
import logging
import tempfile
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from utils.helpers import safe_request

logger = logging.getLogger(__name__)


class ReverseImageSearch:
    """Submit images for reverse search and extract embedded intelligence."""

    # ──────────────────────────────────────────────────────────
    # GENERATE SEARCH URLS
    # ──────────────────────────────────────────────────────────
    def generate_search_urls(self, image_url: str) -> Dict:
        """Generate reverse image search URLs for all major engines."""
        import urllib.parse
        enc = urllib.parse.quote_plus(image_url)
        return {
            "image_url": image_url,
            "engines": {
                "google":  f"https://www.google.com/searchbyimage?image_url={enc}",
                "yandex":  f"https://yandex.com/images/search?url={enc}&rpt=imageview",
                "bing":    f"https://www.bing.com/images/search?q=imgurl:{enc}&view=detailv2&iss=sbi",
                "tineye":  f"https://tineye.com/search?url={enc}",
                "baidu":   f"https://graph.baidu.com/details?isfrom=PC&tn=pc&idctag=graph&frm=&image={enc}",
            },
            "instructions": "Open these URLs in a browser to view reverse image search results.",
        }

    # ──────────────────────────────────────────────────────────
    # TINEYE API (requires key) or scrape
    # ──────────────────────────────────────────────────────────
    def tineye_lookup(self, image_url: str, tineye_key: str = "") -> Dict:
        """Submit image to TinEye for reverse search."""
        if tineye_key:
            resp = safe_request(
                "https://api.tineye.com/rest/search/",
                params={"image_url": image_url, "api_key": tineye_key}
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                return {
                    "source":   "tineye",
                    "matches":  data.get("results", {}).get("total_results", 0),
                    "results":  data.get("results", {}).get("matches", [])[:10],
                }
        return {
            "source":   "tineye",
            "url":      f"https://tineye.com/search?url={image_url}",
            "note":     "Open URL in browser to see results. TinEye API key not configured.",
        }

    # ──────────────────────────────────────────────────────────
    # OCR — Extract text from image
    # ──────────────────────────────────────────────────────────
    def extract_text_from_image(self, image_source: str) -> Dict:
        """Extract text from an image using OCR (Tesseract or free API fallback)."""
        result = {"source": image_source, "text": "", "method": None}

        # Try pytesseract
        try:
            import pytesseract
            from PIL import Image
            import requests

            if image_source.startswith("http"):
                resp = safe_request(image_source)
                if not resp:
                    result["error"] = "Could not download image"
                    return result
                with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
                    f.write(resp.content)
                    tmp_path = f.name
                img = Image.open(tmp_path)
                os.unlink(tmp_path)
            else:
                img = Image.open(image_source)

            text = pytesseract.image_to_string(img)
            result["text"]   = text.strip()
            result["method"] = "tesseract"
            return result
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[OCR] Tesseract error: {e}")

        # Free OCR.space API fallback
        try:
            if image_source.startswith("http"):
                payload = {"url": image_source, "apikey": "helloworld",
                           "language": "eng", "isOverlayRequired": False}
            else:
                with open(image_source, "rb") as f:
                    img_b64 = base64.b64encode(f.read()).decode()
                payload = {"base64image": f"data:image/jpeg;base64,{img_b64}",
                           "apikey": "helloworld", "language": "eng",
                           "isOverlayRequired": False}

            resp = safe_request("https://api.ocr.space/parse/image",
                                json_data=payload, method="POST")
            if resp and resp.status_code == 200:
                parsed = resp.json().get("ParsedResults", [])
                if parsed:
                    result["text"]   = parsed[0].get("ParsedText", "").strip()
                    result["method"] = "ocr.space"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ──────────────────────────────────────────────────────────
    # IMAGE METADATA + HASH
    # ──────────────────────────────────────────────────────────
    def analyze_image(self, image_source: str) -> Dict:
        """Comprehensive image analysis: hash, dimensions, EXIF, search URLs, OCR."""
        result = {
            "source":       image_source,
            "hashes":       {},
            "dimensions":   {},
            "format":       None,
            "search_urls":  {},
            "ocr_text":     "",
            "exif_summary": {},
        }

        # Download if URL
        img_data = None
        if image_source.startswith("http"):
            resp = safe_request(image_source)
            if resp:
                img_data = resp.content
                result["search_urls"] = self.generate_search_urls(image_source)["engines"]
        else:
            with open(image_source, "rb") as f:
                img_data = f.read()

        if not img_data:
            result["error"] = "Could not load image"
            return result

        # Hash the image
        import hashlib
        result["hashes"] = {
            "md5":    hashlib.md5(img_data).hexdigest(),
            "sha1":   hashlib.sha1(img_data).hexdigest(),
            "sha256": hashlib.sha256(img_data).hexdigest(),
        }

        # PIL info
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(img_data))
            result["dimensions"] = {"width": img.width, "height": img.height}
            result["format"]     = img.format
            result["mode"]       = img.mode
        except Exception:
            pass

        # OCR
        ocr = self.extract_text_from_image(image_source)
        result["ocr_text"] = ocr.get("text", "")

        return result
