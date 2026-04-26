"""
modules/phone_lookup.py — Phone number intelligence: validation, carrier, geolocation
"""

import logging
from typing import Dict
from utils.helpers import safe_request
from config import ABSTRACTAPI_PHONE_KEY, NUMVERIFY_API_KEY

logger = logging.getLogger(__name__)

class PhoneLookup:
    """Phone number OSINT: format validation, carrier, region, and open-source lookups."""

    def lookup(self, phone: str) -> Dict:
        result = {
            "input":        phone,
            "parsed":       {},
            "carrier":      None,
            "line_type":    None,
            "country":      None,
            "region":       None,
            "valid":        False,
            "abstractapi":  {},
            "numverify":    {},
        }

        # Parse with phonenumbers library
        parsed = self._parse_number(phone)
        result["parsed"] = parsed
        result["valid"]  = parsed.get("valid", False)

        if result["valid"]:
            result["country"] = parsed.get("country")
            result["region"]  = parsed.get("region")
            result["carrier"] = parsed.get("carrier")
            result["line_type"] = parsed.get("line_type")

        # External API enrichment
        if ABSTRACTAPI_PHONE_KEY:
            result["abstractapi"] = self._abstractapi_lookup(phone)

        if NUMVERIFY_API_KEY:
            result["numverify"] = self._numverify_lookup(phone)

        return result

    def _parse_number(self, phone: str) -> Dict:
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, number_type, NumberParseException, PhoneNumberType

            pn = phonenumbers.parse(phone, None)
            valid = phonenumbers.is_valid_number(pn)

            type_map = {
                PhoneNumberType.MOBILE:         "Mobile",
                PhoneNumberType.FIXED_LINE:     "Fixed Line",
                PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
                PhoneNumberType.TOLL_FREE:      "Toll Free",
                PhoneNumberType.PREMIUM_RATE:   "Premium Rate",
                PhoneNumberType.VOIP:           "VoIP",
                PhoneNumberType.UNKNOWN:        "Unknown",
            }
            line_t = type_map.get(number_type(pn), "Unknown")
            carrier_name = carrier.name_for_number(pn, "en")
            country = geocoder.country_name_for_number(pn, "en")
            region  = geocoder.description_for_number(pn, "en")

            return {
                "valid":            valid,
                "international":    phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "e164":             phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164),
                "national":         phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL),
                "country_code":     pn.country_code,
                "national_number":  pn.national_number,
                "carrier":          carrier_name or "Unknown",
                "country":          country,
                "region":           region,
                "line_type":        line_t,
                "possible":         phonenumbers.is_possible_number(pn),
            }
        except ImportError:
            return {"error": "phonenumbers library not installed. Run: pip install phonenumbers"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _abstractapi_lookup(self, phone: str) -> Dict:
        resp = safe_request(
            "https://phonevalidation.abstractapi.com/v1/",
            params={"api_key": ABSTRACTAPI_PHONE_KEY, "phone": phone}
        )
        if resp and resp.status_code == 200:
            return resp.json()
        return {}

    def _numverify_lookup(self, phone: str) -> Dict:
        resp = safe_request(
            "http://apilayer.net/api/validate",
            params={
                "access_key": NUMVERIFY_API_KEY,
                "number":     phone,
                "country_code": "",
                "format":     "1",
            }
        )
        if resp and resp.status_code == 200:
            return resp.json()
        return {}
