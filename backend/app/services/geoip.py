"""Offline GeoIP lookup backed by a local MaxMind GeoLite2 database.

No per-request external API calls — everything resolves locally via the
`geoip2` package. Download GeoLite2-City.mmdb from MaxMind (free account) and
set GEOIP_DB_PATH in the backend .env. All failures (missing DB, private or
reserved IPs, bad IP strings) return None instead of raising.
"""

import ipaddress
import logging
import os

from app.config import GEOIP_DB_PATH

logger = logging.getLogger(__name__)

_reader = None
_load_error = None


def _get_reader():
    global _reader, _load_error
    if _reader is not None or _load_error is not None:
        return _reader
    if not GEOIP_DB_PATH:
        _load_error = "GEOIP_DB_PATH not configured"
        logger.info("GeoIP enrichment disabled: %s", _load_error)
        return None
    if not os.path.exists(GEOIP_DB_PATH):
        _load_error = f"GeoIP database not found at {GEOIP_DB_PATH}"
        logger.warning(_load_error)
        return None
    try:
        import geoip2.database  # noqa: PLC0415 - lazy import, optional dependency

        _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP database loaded from %s", GEOIP_DB_PATH)
    except Exception as e:  # noqa: BLE001 - any failure disables lookup, never raises
        _load_error = f"Failed to load GeoIP database: {e}"
        logger.warning(_load_error)
    return _reader


def lookup(ip: str) -> dict | None:
    """Return {country, city, lat, lon} for a public IP, or None on any failure."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None

    reader = _get_reader()
    if reader is None:
        return None

    try:
        resp = reader.city(ip)
    except Exception:
        return None

    return {
        "country": resp.country.iso_code or resp.country.name or "",
        "city": resp.city.name or "",
        "lat": resp.location.latitude,
        "lon": resp.location.longitude,
    }
