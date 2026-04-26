"""
modules/metadata_extractor.py — EXIF, PDF, DOCX and image metadata extraction
"""

import os
import re
import logging
from typing import Dict, Any
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

class MetadataExtractor:
    """Extract metadata from images, PDFs, and other documents."""

    # ─────────────────────────────────────────────
    # IMAGE EXIF DATA
    # ─────────────────────────────────────────────
    def extract_image_metadata(self, filepath: str) -> Dict:
        result = {
            "file":     filepath,
            "type":     "image",
            "exif":     {},
            "gps":      {},
            "camera":   {},
            "software": {},
        }

        # Try exifread first
        try:
            import exifread
            with open(filepath, "rb") as f:
                tags = exifread.process_file(f, details=False)
            for key, value in tags.items():
                result["exif"][key] = str(value)

            # GPS extraction
            gps = self._extract_gps_from_exif(tags)
            if gps:
                result["gps"] = gps

            # Camera info
            for field in ["Image Make", "Image Model", "EXIF LensModel", "EXIF FocalLength"]:
                if field in tags:
                    result["camera"][field] = str(tags[field])

            # Software info
            for field in ["Image Software", "EXIF Software"]:
                if field in tags:
                    result["software"][field] = str(tags[field])

        except ImportError:
            result["exif"]["error"] = "exifread not installed"
        except Exception as e:
            result["exif"]["error"] = str(e)

        # Pillow fallback for basic info
        try:
            from PIL import Image, ExifTags
            img = Image.open(filepath)
            result["dimensions"] = {"width": img.width, "height": img.height}
            result["format"]     = img.format
            result["mode"]       = img.mode

            pil_exif = img._getexif()
            if pil_exif:
                for tag_id, value in pil_exif.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    if tag not in result["exif"]:
                        result["exif"][str(tag)] = str(value)
        except Exception:
            pass

        return result

    def _extract_gps_from_exif(self, tags: dict) -> Dict:
        """Convert EXIF GPS IFD values to decimal coordinates."""
        try:
            import exifread

            def _convert_to_degrees(value):
                d = float(value.values[0].num) / float(value.values[0].den)
                m = float(value.values[1].num) / float(value.values[1].den)
                s = float(value.values[2].num) / float(value.values[2].den)
                return d + (m / 60.0) + (s / 3600.0)

            lat  = tags.get("GPS GPSLatitude")
            lat_ref  = tags.get("GPS GPSLatitudeRef")
            lon  = tags.get("GPS GPSLongitude")
            lon_ref  = tags.get("GPS GPSLongitudeRef")
            alt  = tags.get("GPS GPSAltitude")

            if lat and lon:
                lat_val = _convert_to_degrees(lat)
                lon_val = _convert_to_degrees(lon)
                if lat_ref and str(lat_ref) == "S":
                    lat_val = -lat_val
                if lon_ref and str(lon_ref) == "W":
                    lon_val = -lon_val
                gps = {
                    "latitude":  round(lat_val, 6),
                    "longitude": round(lon_val, 6),
                    "maps_link": f"https://maps.google.com/?q={lat_val},{lon_val}",
                }
                if alt:
                    gps["altitude"] = str(alt)
                return gps
        except Exception:
            pass
        return {}

    # ─────────────────────────────────────────────
    # PDF METADATA
    # ─────────────────────────────────────────────
    def extract_pdf_metadata(self, filepath: str) -> Dict:
        result = {"file": filepath, "type": "pdf", "metadata": {}}
        try:
            import PyPDF2
            with open(filepath, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata
                result["pages"] = len(reader.pages)
                result["metadata"] = {
                    "title":    info.get("/Title", ""),
                    "author":   info.get("/Author", ""),
                    "subject":  info.get("/Subject", ""),
                    "creator":  info.get("/Creator", ""),
                    "producer": info.get("/Producer", ""),
                    "created":  info.get("/CreationDate", ""),
                    "modified": info.get("/ModDate", ""),
                    "keywords": info.get("/Keywords", ""),
                }
                # Extract text from first page for analysis
                try:
                    first_page_text = reader.pages[0].extract_text()
                    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", first_page_text)
                    result["emails_found"] = list(set(emails))
                except Exception:
                    pass
        except ImportError:
            result["error"] = "PyPDF2 not installed. Run: pip install PyPDF2"
        except Exception as e:
            result["error"] = str(e)
        return result

    # ─────────────────────────────────────────────
    # DOCX METADATA
    # ─────────────────────────────────────────────
    def extract_docx_metadata(self, filepath: str) -> Dict:
        result = {"file": filepath, "type": "docx", "metadata": {}}
        try:
            from docx import Document
            doc = Document(filepath)
            props = doc.core_properties
            result["metadata"] = {
                "author":           props.author,
                "last_modified_by": props.last_modified_by,
                "created":          str(props.created),
                "modified":         str(props.modified),
                "title":            props.title,
                "subject":          props.subject,
                "description":      props.description,
                "keywords":         props.keywords,
                "category":         props.category,
                "revision":         props.revision,
            }
        except ImportError:
            result["error"] = "python-docx not installed. Run: pip install python-docx"
        except Exception as e:
            result["error"] = str(e)
        return result

    # ─────────────────────────────────────────────
    # REMOTE URL METADATA
    # ─────────────────────────────────────────────
    def extract_from_url(self, url: str) -> Dict:
        """Download a remote file and extract its metadata."""
        import tempfile
        result = {"url": url, "metadata": {}}

        resp = safe_request(url)
        if not resp or resp.status_code != 200:
            result["error"] = "Could not download file"
            return result

        content_type = resp.headers.get("Content-Type", "")
        ext = ""
        if "image" in content_type:
            ext = ".jpg"
        elif "pdf" in content_type:
            ext = ".pdf"
        else:
            ext = ".bin"

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name

        try:
            if ext == ".jpg":
                result = self.extract_image_metadata(tmp_path)
            elif ext == ".pdf":
                result = self.extract_pdf_metadata(tmp_path)
            result["source_url"] = url
        finally:
            os.unlink(tmp_path)

        return result

    # ─────────────────────────────────────────────
    # AUTO-DETECT
    # ─────────────────────────────────────────────
    def extract(self, source: str) -> Dict:
        """Auto-detect source type and extract metadata."""
        if source.startswith("http://") or source.startswith("https://"):
            return self.extract_from_url(source)
        elif not os.path.exists(source):
            return {"error": f"File not found: {source}"}
        elif source.lower().endswith(".pdf"):
            return self.extract_pdf_metadata(source)
        elif source.lower().endswith(".docx"):
            return self.extract_docx_metadata(source)
        else:
            return self.extract_image_metadata(source)
