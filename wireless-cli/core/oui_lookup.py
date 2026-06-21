"""
MAC OUI (Organizationally Unique Identifier) → vendor lookup.

Backed by core/oui_db.txt — a tab-separated PREFIX\tVENDOR file derived from
the IEEE registration authority (sourced via nmap's mirrored database).
Loaded once into memory at import time; lookups are O(1) dict access.
"""

import os
from pathlib import Path

_OUI_DB_PATH = Path(__file__).parent / "oui_db.txt"
_oui_map: dict = {}


def _load() -> None:
    global _oui_map
    if _oui_map:
        return
    if not _OUI_DB_PATH.exists():
        return
    with open(_OUI_DB_PATH, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or "\t" not in line:
                continue
            prefix, vendor = line.split("\t", 1)
            _oui_map[prefix.strip().upper()] = vendor.strip()


def lookup_vendor(mac: str) -> str:
    """Return the vendor name for a MAC address, or '' if unknown.

    Accepts MACs in any common notation (colon, dash, or bare hex).
    """
    if not mac:
        return ""
    _load()
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 6:
        return ""
    prefix = clean[:6]
    return _oui_map.get(prefix, "")


def is_locally_administered(mac: str) -> bool:
    """Return True if the MAC's locally-administered bit is set
    (i.e. it's a randomized/spoofed MAC, not a real vendor address)."""
    if not mac:
        return False
    clean = mac.upper().replace(":", "").replace("-", "")
    if len(clean) < 2:
        return False
    try:
        first_octet = int(clean[:2], 16)
        return bool(first_octet & 0b00000010)
    except ValueError:
        return False
