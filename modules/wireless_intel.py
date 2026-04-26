"""
modules/wireless_intel.py — WiFi & Bluetooth OSINT
WiGLE API for network geolocation, MAC OUI lookup, BSSID/SSID search
"""

import re
import logging
from typing import Dict, List, Optional
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

WIGLE_API   = "https://api.wigle.net/api/v2"
OUI_DB_URL  = "https://www.macvendorlookup.com/api/v2"
MACLOOKUP   = "https://api.maclookup.app/v2/macs"


class WirelessIntel:
    """WiFi & Bluetooth OSINT — network geolocation, device identification."""

    def __init__(self, wigle_key: str = ""):
        self.wigle_key = wigle_key

    # ──────────────────────────────────────────────────────────
    # MAC ADDRESS / OUI LOOKUP
    # ──────────────────────────────────────────────────────────
    def mac_lookup(self, mac: str) -> Dict:
        """Identify the manufacturer of a device from its MAC address."""
        # Normalize MAC format
        mac_clean = re.sub(r"[^a-fA-F0-9]", "", mac).upper()
        if len(mac_clean) < 6:
            return {"error": "Invalid MAC address format", "input": mac}

        mac_formatted = ":".join(mac_clean[i:i+2] for i in range(0, min(12, len(mac_clean)), 2))
        oui = mac_clean[:6]

        result = {"mac": mac_formatted, "oui": oui, "vendor": None,
                  "is_multicast": (int(mac_clean[0:2], 16) & 1) == 1,
                  "is_locally_administered": (int(mac_clean[0:2], 16) & 2) == 2}

        # macalookup.app (free)
        resp = safe_request(f"{MACLOOKUP}/{mac_formatted}")
        if resp and resp.status_code == 200:
            data = resp.json()
            result["vendor"]   = data.get("company")
            result["country"]  = data.get("country")
            result["type"]     = data.get("type")
            result["is_private"] = data.get("isPrivate", False)
            return result

        # Fallback: macvendorlookup.com
        resp2 = safe_request(f"{OUI_DB_URL}/{mac_formatted}")
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                if isinstance(data, list) and data:
                    result["vendor"]   = data[0].get("company")
                    result["country"]  = data[0].get("country")
                    result["address"]  = data[0].get("addressL1")
            except Exception:
                pass

        return result

    # ──────────────────────────────────────────────────────────
    # WIGLE — SSID/BSSID SEARCH
    # ──────────────────────────────────────────────────────────
    def wigle_ssid_search(self, ssid: str) -> Dict:
        """Search WiGLE for a WiFi network by SSID name."""
        if not self.wigle_key:
            return {
                "ssid": ssid,
                "note": ("WiGLE API key not configured. "
                         "Sign up free at wigle.net and set WIGLE_KEY in .env"),
                "wigle_url": f"https://wigle.net/search#search={ssid}",
            }

        resp = safe_request(
            f"{WIGLE_API}/network/search",
            params={"ssid": ssid, "resultsPerPage": 20},
            headers={"Authorization": f"Basic {self.wigle_key}"},
        )

        if not resp or resp.status_code != 200:
            return {"ssid": ssid, "error": "WiGLE search failed"}

        data    = resp.json()
        results = data.get("results", [])

        networks = []
        for r in results:
            networks.append({
                "ssid":          r.get("ssid"),
                "bssid":         r.get("netid"),
                "encryption":    r.get("encryption"),
                "channel":       r.get("channel"),
                "frequency":     r.get("freqMhz"),
                "lat":           r.get("trilat"),
                "lon":           r.get("trilong"),
                "country":       r.get("country"),
                "region":        r.get("region"),
                "city":          r.get("city"),
                "road":          r.get("road"),
                "first_seen":    r.get("firsttime"),
                "last_seen":     r.get("lasttime"),
                "signal_strength": r.get("rssi"),
            })

        return {
            "ssid":          ssid,
            "total_found":   data.get("totalResults", 0),
            "networks":      networks,
            "note":          "Coordinates show approximate real-world location of the network",
        }

    def wigle_bssid_lookup(self, bssid: str) -> Dict:
        """Look up a specific access point by BSSID/MAC address."""
        if not self.wigle_key:
            return {"bssid": bssid, "note": "WIGLE_KEY not configured"}

        bssid_clean = bssid.upper().replace("-",":")
        resp = safe_request(
            f"{WIGLE_API}/network/search",
            params={"netid": bssid_clean, "resultsPerPage": 5},
            headers={"Authorization": f"Basic {self.wigle_key}"},
        )
        if not resp or resp.status_code != 200:
            return {"bssid": bssid, "error": "WiGLE lookup failed"}

        data    = resp.json()
        results = data.get("results", [])

        if not results:
            return {"bssid": bssid, "found": False}

        r = results[0]
        mac_info = self.mac_lookup(bssid)
        return {
            "bssid":     bssid,
            "found":     True,
            "ssid":      r.get("ssid"),
            "lat":       r.get("trilat"),
            "lon":       r.get("trilong"),
            "city":      r.get("city"),
            "region":    r.get("region"),
            "country":   r.get("country"),
            "road":      r.get("road"),
            "encryption":r.get("encryption"),
            "first_seen":r.get("firsttime"),
            "last_seen": r.get("lasttime"),
            "vendor":    mac_info.get("vendor"),
            "maps_link": f"https://maps.google.com/?q={r.get('trilat')},{r.get('trilong')}"
                         if r.get("trilat") else None,
        }

    # ──────────────────────────────────────────────────────────
    # BLUETOOTH OUI LOOKUP
    # ──────────────────────────────────────────────────────────
    def bluetooth_lookup(self, bt_address: str) -> Dict:
        """Identify a Bluetooth device manufacturer from its address."""
        # BT addresses use same OUI structure as MAC addresses
        mac_info = self.mac_lookup(bt_address)
        mac_info["device_type"] = "bluetooth"

        # Classify common BT device types by vendor
        vendor = (mac_info.get("vendor") or "").lower()
        device_hints = []
        if any(k in vendor for k in ["apple", "samsung", "google"]):
            device_hints.append("likely smartphone/tablet")
        if any(k in vendor for k in ["bose", "sony", "jabra", "sennheiser", "jbl"]):
            device_hints.append("likely audio device (headphones/speaker)")
        if any(k in vendor for k in ["fitbit", "garmin", "polar", "wahoo"]):
            device_hints.append("likely fitness tracker/smartwatch")
        if any(k in vendor for k in ["logitech", "microsoft"]):
            device_hints.append("likely peripheral (mouse/keyboard)")
        if any(k in vendor for k in ["tile", "chipolo"]):
            device_hints.append("likely asset tracker")

        mac_info["device_hints"] = device_hints
        return mac_info

    # ──────────────────────────────────────────────────────────
    # FULL PROFILE
    # ──────────────────────────────────────────────────────────
    def full_wireless_profile(self, target: str) -> Dict:
        """
        Auto-detect target type (SSID, BSSID/MAC) and run appropriate lookups.
        """
        is_mac = bool(re.match(
            r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$", target))

        if is_mac:
            return {
                "target": target,
                "type":   "mac_bssid",
                "mac_vendor":     self.mac_lookup(target),
                "wigle_location": self.wigle_bssid_lookup(target),
            }
        else:
            return {
                "target":       target,
                "type":         "ssid",
                "wigle_search": self.wigle_ssid_search(target),
            }
