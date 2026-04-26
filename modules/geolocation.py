"""
modules/geolocation.py — IP/domain geolocation, GPS coordinate mapping, reverse geocoding
"""

import logging
from typing import Dict, Optional, Tuple
from utils.helpers import safe_request
from config import IPINFO_TOKEN

logger = logging.getLogger(__name__)

class GeoLocation:
    """Geolocation intelligence for IPs, domains, GPS coordinates."""

    # ─────────────────────────────────────────────
    # IP GEOLOCATION
    # ─────────────────────────────────────────────
    def ip_geolocation(self, ip: str) -> Dict:
        result = {"ip": ip, "location": {}, "network": {}, "map_url": None}

        # IPInfo (primary)
        token_suffix = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
        resp = safe_request(f"https://ipinfo.io/{ip}/json{token_suffix}")
        if resp and resp.status_code == 200:
            data = resp.json()
            loc_str = data.get("loc", "0,0")
            lat, lon = loc_str.split(",") if "," in loc_str else ("0", "0")
            result["location"] = {
                "city":         data.get("city"),
                "region":       data.get("region"),
                "country":      data.get("country"),
                "postal":       data.get("postal"),
                "timezone":     data.get("timezone"),
                "latitude":     float(lat),
                "longitude":    float(lon),
            }
            result["network"] = {
                "org":      data.get("org"),
                "hostname": data.get("hostname"),
                "asn":      data.get("org", "").split(" ")[0] if data.get("org") else None,
            }
            lat_f, lon_f = float(lat), float(lon)
            result["map_url"] = f"https://maps.google.com/?q={lat_f},{lon_f}"

        # ip-api.com fallback (no key needed)
        if not result["location"]:
            resp2 = safe_request(f"http://ip-api.com/json/{ip}")
            if resp2 and resp2.status_code == 200:
                d = resp2.json()
                if d.get("status") == "success":
                    result["location"] = {
                        "city":      d.get("city"),
                        "region":    d.get("regionName"),
                        "country":   d.get("country"),
                        "postal":    d.get("zip"),
                        "timezone":  d.get("timezone"),
                        "latitude":  d.get("lat"),
                        "longitude": d.get("lon"),
                    }
                    result["network"] = {
                        "org":  d.get("org"),
                        "isp":  d.get("isp"),
                        "asn":  d.get("as"),
                    }
                    result["map_url"] = f"https://maps.google.com/?q={d.get('lat')},{d.get('lon')}"

        return result

    # ─────────────────────────────────────────────
    # DOMAIN → IP → GEOLOCATION
    # ─────────────────────────────────────────────
    def domain_geolocation(self, domain: str) -> Dict:
        import socket
        from utils.helpers import clean_domain
        domain = clean_domain(domain)
        try:
            ip = socket.gethostbyname(domain)
            result = self.ip_geolocation(ip)
            result["domain"] = domain
            result["resolved_ip"] = ip
            return result
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    # ─────────────────────────────────────────────
    # GPS COORDINATE REVERSE GEOCODING
    # ─────────────────────────────────────────────
    def reverse_geocode(self, lat: float, lon: float) -> Dict:
        """Convert GPS coordinates to a human-readable address."""
        result = {
            "latitude":  lat,
            "longitude": lon,
            "address":   {},
            "map_url":   f"https://maps.google.com/?q={lat},{lon}",
        }

        resp = safe_request(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json"},
            headers={"User-Agent": "OSINT-Tool/1.0 (research purposes)"},
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            result["address"] = {
                "display":    data.get("display_name"),
                "road":       data.get("address", {}).get("road"),
                "city":       data.get("address", {}).get("city") or data.get("address", {}).get("town"),
                "county":     data.get("address", {}).get("county"),
                "state":      data.get("address", {}).get("state"),
                "country":    data.get("address", {}).get("country"),
                "postcode":   data.get("address", {}).get("postcode"),
                "country_code": data.get("address", {}).get("country_code"),
            }
        return result

    # ─────────────────────────────────────────────
    # FORWARD GEOCODING
    # ─────────────────────────────────────────────
    def geocode(self, address: str) -> Dict:
        """Convert address string to GPS coordinates."""
        resp = safe_request(
            "https://nominatim.openstreetmap.org/search",
            params={"q": address, "format": "json", "limit": 1},
            headers={"User-Agent": "OSINT-Tool/1.0 (research purposes)"},
        )
        if resp and resp.status_code == 200:
            results = resp.json()
            if results:
                r = results[0]
                lat, lon = float(r["lat"]), float(r["lon"])
                return {
                    "address":    address,
                    "latitude":   lat,
                    "longitude":  lon,
                    "display":    r.get("display_name"),
                    "type":       r.get("type"),
                    "map_url":    f"https://maps.google.com/?q={lat},{lon}",
                }
        return {"address": address, "error": "Geocoding failed"}

    # ─────────────────────────────────────────────
    # GENERATE FOLIUM MAP
    # ─────────────────────────────────────────────
    def generate_map(self, locations: list, output_path: str = "output/geo_map.html") -> str:
        """
        Generate an interactive HTML map from a list of location dicts.
        Each location: {"lat": float, "lon": float, "label": str, "info": str}
        """
        try:
            import folium
            import os
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            if not locations:
                return ""

            center_lat = sum(l["lat"] for l in locations) / len(locations)
            center_lon = sum(l["lon"] for l in locations) / len(locations)

            m = folium.Map(location=[center_lat, center_lon], zoom_start=5)

            for loc in locations:
                folium.Marker(
                    location=[loc["lat"], loc["lon"]],
                    popup=folium.Popup(f"<b>{loc.get('label','?')}</b><br>{loc.get('info','')}", max_width=300),
                    tooltip=loc.get("label", ""),
                    icon=folium.Icon(color="red", icon="info-sign"),
                ).add_to(m)

            m.save(output_path)
            logger.info(f"[GEO] Map saved to {output_path}")
            return output_path
        except ImportError:
            return "folium not installed. Run: pip install folium"
        except Exception as e:
            return str(e)
