import re

def sanitize_ssid(ssid: str) -> str:
    """Validate and return an SSID.

    802.11 allows any byte sequence up to 32 bytes in an SSID, but for
    hostapd config-file safety we permit the printable ASCII subset that
    covers the overwhelming majority of real-world SSIDs.

    BUG FIX (original): regex only allowed [\\w\\s\\-\\.@!], which rejects
    common valid SSIDs like "Cafe&Bar", "O'Brien's", "Net#1", "Corp(2)",
    "WiFi+Pass", etc.  Expanded the allowlist to cover the full printable
    ASCII range except for characters that are dangerous in a hostapd .conf
    file (newline, carriage-return, NUL) or shell-injectable when
    concatenated into shell strings (backtick, dollar).
    Also added a 32-byte length cap per IEEE 802.11.
    """
    if not ssid:
        raise ValueError("SSID cannot be empty")
    if len(ssid.encode("utf-8")) > 32:
        raise ValueError("SSID exceeds 32-byte IEEE 802.11 limit")
    # Allow printable ASCII except control chars and chars that break hostapd
    # config format (\n \r \0) or enable injection (` $)
    if not re.match(r'^[ -~]+$', ssid) or any(c in ssid for c in ('\n', '\r', '\x00', '`', '$')):
        raise ValueError("SSID contains characters not safe for hostapd config")
    return ssid

def sanitize_filename(name: str) -> str:
    return re.sub(r'[^\w\-]', '_', name)
