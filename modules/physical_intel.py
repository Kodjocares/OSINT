"""
modules/physical_intel.py — Vehicle & physical asset OSINT
VIN decode, aircraft registration, vessel tracking, license plate info
"""

import re
import logging
from typing import Dict, Optional
from utils.helpers import safe_request
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

FAA_API      = "https://registry.faa.gov/aircraftinquiry/Search"
OPENSKY_API  = "https://opensky-network.org/api"
MARINE_API   = "https://www.marinetraffic.com/api"
NHTSA_API    = "https://vpic.nhtsa.dot.gov/api/vehicles"


class PhysicalIntel:
    """Vehicle & physical asset intelligence — VIN, aircraft, vessels."""

    def __init__(self, marinetraffic_key: str = ""):
        self.marine_key = marinetraffic_key

    # ──────────────────────────────────────────────────────────
    # VIN DECODER (NHTSA — free, no key)
    # ──────────────────────────────────────────────────────────
    def decode_vin(self, vin: str) -> Dict:
        """Decode a Vehicle Identification Number using NHTSA free API."""
        vin = vin.strip().upper()
        if not re.match(r"^[A-HJ-NPR-Z0-9]{17}$", vin):
            return {"error": "Invalid VIN — must be 17 characters (no I, O, Q)", "vin": vin}

        resp = safe_request(
            f"{NHTSA_API}/DecodeVinValues/{vin}",
            params={"format": "json"}
        )
        if not resp or resp.status_code != 200:
            return {"error": "NHTSA API unavailable", "vin": vin}

        try:
            data   = resp.json()
            result = data.get("Results", [{}])[0]
        except Exception:
            return {"error": "Parse error", "vin": vin}

        def get(key: str) -> Optional[str]:
            v = result.get(key, "")
            return v if v and v.strip() else None

        return {
            "vin":            vin,
            "year":           get("ModelYear"),
            "make":           get("Make"),
            "model":          get("Model"),
            "trim":           get("Trim"),
            "body_style":     get("BodyClass"),
            "vehicle_type":   get("VehicleType"),
            "engine":         get("DisplacementL"),
            "cylinders":      get("EngineCylinders"),
            "fuel_type":      get("FuelTypePrimary"),
            "transmission":   get("TransmissionStyle"),
            "drive_type":     get("DriveType"),
            "doors":          get("Doors"),
            "series":         get("Series"),
            "manufacturer":   get("Manufacturer"),
            "plant_country":  get("PlantCountry"),
            "plant_city":     get("PlantCity"),
            "plant_state":    get("PlantState"),
            "wmi":            vin[:3],
            "vds":            vin[3:9],
            "check_digit":    vin[8],
            "sequential":     vin[12:],
            "recall_check":   f"https://www.nhtsa.gov/vehicle/{vin}",
        }

    def vin_recalls(self, vin: str) -> Dict:
        """Check NHTSA recall database for a VIN."""
        vin = vin.strip().upper()
        resp = safe_request(
            f"https://api.nhtsa.gov/recalls/recallsByVehicle",
            params={"vin": vin}
        )
        if resp and resp.status_code == 200:
            data    = resp.json()
            recalls = data.get("results", [])
            return {
                "vin":      vin,
                "count":    len(recalls),
                "recalls":  [{
                    "campaign":    r.get("NHTSACampaignNumber"),
                    "component":   r.get("Component"),
                    "description": r.get("Summary","")[:200],
                    "remedy":      r.get("Remedy","")[:100],
                    "report_date": r.get("ReportReceivedDate"),
                } for r in recalls],
            }
        return {"vin": vin, "error": "NHTSA recall API unavailable"}

    # ──────────────────────────────────────────────────────────
    # AIRCRAFT REGISTRATION (FAA — free, no key)
    # ──────────────────────────────────────────────────────────
    def faa_aircraft_lookup(self, n_number: str) -> Dict:
        """Look up US aircraft registration by N-number."""
        n_number = n_number.upper().lstrip("N")
        full_n   = f"N{n_number}"

        resp = safe_request(
            "https://registry.faa.gov/aircraftinquiry/Search/NNumberResult",
            params={"nNumberTxt": full_n}
        )
        if not resp or resp.status_code != 200:
            return {"n_number": full_n, "error": "FAA registry unavailable"}

        soup = BeautifulSoup(resp.text, "lxml")
        result = {"n_number": full_n, "registered": False}

        # Parse registration table
        tables = soup.find_all("table")
        for table in tables:
            for row in table.find_all("tr"):
                cells = row.find_all(["th","td"])
                if len(cells) >= 2:
                    label = cells[0].get_text(strip=True).lower()
                    value = cells[1].get_text(strip=True)
                    if value:
                        result["registered"] = True
                        if "serial" in label:     result["serial_number"] = value
                        if "manufacturer" in label: result["manufacturer"] = value
                        if "model" in label:      result["model"] = value
                        if "year" in label:       result["year"] = value
                        if "type" in label and "registrant" not in label: result["type"] = value
                        if "registrant" in label or "owner" in label: result["owner"] = value
                        if "address" in label:    result["address"] = value
                        if "status" in label:     result["status"] = value
                        if "expir" in label:      result["expiry"] = value
                        if "airworth" in label:   result["airworthiness"] = value

        if result.get("registered"):
            result["faa_url"]  = f"https://registry.faa.gov/aircraftinquiry/Search/NNumberResult?nNumberTxt={full_n}"
            result["flightradar_url"] = f"https://www.flightradar24.com/data/aircraft/{full_n.lower()}"

        return result

    # ──────────────────────────────────────────────────────────
    # OPENSKY — LIVE FLIGHT TRACKING (free, no key)
    # ──────────────────────────────────────────────────────────
    def opensky_aircraft_track(self, icao24: str) -> Dict:
        """Track aircraft by ICAO24 transponder code using OpenSky."""
        icao = icao24.lower().strip()
        resp = safe_request(f"{OPENSKY_API}/states/all",
                            params={"icao24": icao})
        if not resp or resp.status_code != 200:
            return {"icao24": icao, "error": "OpenSky unavailable"}

        data   = resp.json()
        states = data.get("states", [])
        if not states:
            return {"icao24": icao, "airborne": False, "message": "Aircraft not currently airborne"}

        s = states[0]
        return {
            "icao24":      s[0],
            "callsign":    (s[1] or "").strip(),
            "origin_country": s[2],
            "last_contact":s[4],
            "longitude":   s[5],
            "latitude":    s[6],
            "altitude_m":  s[7],
            "on_ground":   s[8],
            "velocity_ms": s[9],
            "true_track":  s[10],
            "vertical_rate":s[11],
            "airborne":    not s[8],
            "opensky_url": f"https://opensky-network.org/aircraft-profile?icao24={icao}",
        }

    def opensky_by_registration(self, registration: str) -> Dict:
        """Look up an aircraft by registration in OpenSky metadata."""
        resp = safe_request(
            f"{OPENSKY_API}/metadata/aircraft/icao24/{registration.lower()}"
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            return {
                "registration": registration,
                "icao24":       data.get("icao24"),
                "manufacturer": data.get("manufacturerName"),
                "model":        data.get("model"),
                "operator":     data.get("operatorIcao"),
                "owner":        data.get("owner"),
                "built":        data.get("built"),
                "engines":      data.get("engines"),
                "category":     data.get("categoryDescription"),
            }
        return {"registration": registration, "error": "Not found in OpenSky metadata"}

    # ──────────────────────────────────────────────────────────
    # VESSEL TRACKING (free via MarineTraffic or VesselFinder)
    # ──────────────────────────────────────────────────────────
    def vessel_lookup(self, mmsi_or_name: str) -> Dict:
        """Look up a vessel by MMSI number or name."""
        # Try VesselFinder free search
        query    = mmsi_or_name.strip()
        search_url = f"https://www.vesselfinder.com/vessels?name={query}"
        resp     = safe_request(search_url)

        result   = {"query": query, "vessels": []}

        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for item in soup.find_all("div", class_="vf-ship")[:5]:
                name   = item.find("div", class_="cell-name")
                country = item.find("span", class_="flag-icon")
                detail = item.find("div", class_="cell-details")
                if name:
                    result["vessels"].append({
                        "name":    name.get_text(strip=True),
                        "country": country.get("title","") if country else None,
                        "detail":  detail.get_text(strip=True)[:100] if detail else None,
                    })

        # MarineTraffic (requires key for full data)
        result["marinetraffic_url"] = f"https://www.marinetraffic.com/en/ais/details/ships/{query}"
        result["vesseltracker_url"] = f"https://www.vesseltracker.com/en/Ships/{query}.html"

        return result

    # ──────────────────────────────────────────────────────────
    # LICENSE PLATE INFO (public data only)
    # ──────────────────────────────────────────────────────────
    def license_plate_info(self, plate: str, state: str = "") -> Dict:
        """
        Provide public information about a license plate format.
        Full DMV lookup requires authorized access — this returns format analysis only.
        """
        plate = plate.strip().upper()

        # Analyze plate format
        patterns = {
            "US_standard":    r"^[A-Z]{1,3}[0-9]{1,4}[A-Z]{0,3}$",
            "US_vanity":      r"^[A-Z0-9]{2,8}$",
            "EU_standard":    r"^[A-Z]{1,2}[0-9]{1,4}[A-Z]{2}$",
            "UK_standard":    r"^[A-Z]{2}[0-9]{2}[A-Z]{3}$",
        }

        fmt = "unknown"
        for name, pattern in patterns.items():
            if re.match(pattern, plate):
                fmt = name
                break

        return {
            "plate":     plate,
            "state":     state,
            "format":    fmt,
            "length":    len(plate),
            "note":      ("Full DMV records require law enforcement or licensed access. "
                          "This module returns format analysis only."),
            "public_resources": [
                f"https://www.vehiclehistory.com/license-plate-search/{plate}",
                f"https://www.autocheck.com/vehiclehistory/vin-check",
            ],
        }
