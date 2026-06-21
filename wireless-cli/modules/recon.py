"""
Passive recon: live-updating table of discovered APs and clients via
airodump-ng, with OUI vendor lookup, auth-type labeling, and SQLite
persistence (so results survive across runs).
"""

import asyncio
import csv
import os
import time
from pathlib import Path

from rich.live import Live
from rich.console import Group

from core.exec_utils import run_command
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process
from core.oui_lookup import lookup_vendor
from core.models import save_recon_ap
from core.display import console, info, ok, warn, err, header, aps_table, clients_table

CAPTURE_DIR = Path("captures")
CSV_PREFIX = CAPTURE_DIR / "recon"

live_aps: dict = {}
live_clients: dict = {}


def _build_auth_label(privacy: str, auth_raw: str) -> str:
    if privacy == "OPN" and "OWE" not in auth_raw:
        return "Open"
    if privacy == "WEP":
        return "WEP (legacy)"
    if "SAE" in auth_raw and "PSK" in auth_raw:
        return "WPA2/WPA3-Personal (SAE+PSK)"
    if "SAE" in auth_raw:
        return "WPA3-Personal (SAE)"
    if "MGT" in auth_raw:
        if "WPA3" in privacy:
            return "WPA3-Enterprise (802.1X)"
        if "WPA2" in privacy:
            return "WPA2-Enterprise (802.1X)"
        return "Enterprise (802.1X)"
    if "PSK" in auth_raw:
        if "WPA3" in privacy and "WPA2" in privacy:
            return "WPA2/WPA3-Personal"
        if "WPA3" in privacy:
            return "WPA3-Personal"
        if "WPA2" in privacy:
            return "WPA2-Personal"
        return "WPA-Personal"
    if "OWE" in auth_raw or "OWE" in privacy:
        return "Enhanced Open (OWE)"
    return privacy or "Unknown"


def _build_vulns(privacy: str, auth_raw: str, cipher: str, wps: str) -> list:
    vuln = []
    if privacy == "WEP":
        vuln.append("WEP Crack")
    if wps == "Yes":
        vuln.append("WPS Pixie-Dust")
    if "WPA" in privacy and "WPA2" not in privacy and "WPA3" not in privacy:
        vuln.append("Legacy WPA (deprecated)")
    if "WPA2" in privacy and "WPA3" not in privacy and "MGT" not in auth_raw:
        vuln.append("KRACK Candidate")
    if "MGT" in auth_raw:
        vuln.append("EAP: enterprise credential capture")
    if "TKIP" in cipher:
        vuln.append("TKIP: MIC / chopchop attack")
    if "OWE" in privacy or "OWE" in auth_raw:
        vuln.append("OWE Downgrade")
    if privacy == "OPN" and "OWE" not in auth_raw:
        vuln.append("Open: no encryption")
    return vuln


_last_csv_mtime: float = 0.0


def _parse_csv(filepath: str, force: bool = False) -> bool:
    """Parse the airodump-ng CSV. Returns False (and does no work) if the
    file's mtime hasn't changed since the last call.

    PERFORMANCE NOTE: airodump-ng fully *rewrites* this file on every
    --write-interval rather than appending — so a byte-offset seek would be
    incorrect here (a line's length can shift between writes as field values
    change). The correct optimization is mtime-based change detection: skip
    the parse, OUI lookups, and SQLite writes entirely on ticks where
    airodump-ng hasn't produced a new write yet.
    """
    global _last_csv_mtime
    try:
        mtime = os.path.getmtime(filepath)
        if not force and mtime == _last_csv_mtime:
            return False
        _last_csv_mtime = mtime
        with open(filepath, "r", newline="") as f:
            lines = f.readlines()
    except Exception:
        return False

    ap_section = True
    ap_lines, client_lines = [], []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("BSSID,"):
            ap_section = True
            ap_lines = [stripped]
        elif stripped.startswith("Station MAC,"):
            ap_section = False
            client_lines = [stripped]
        else:
            (ap_lines if ap_section else client_lines).append(stripped)

    if len(ap_lines) >= 2:
        reader = csv.DictReader(ap_lines, skipinitialspace=True)
        for row in reader:
            bssid = row.get("BSSID", "").strip()
            if not bssid or bssid == "BSSID":
                continue
            channel = row.get("channel", "").strip()
            try:
                ch_num = int(channel)
            except ValueError:
                ch_num = -1
            if ch_num < 1:
                continue  # filter non-WiFi garbage rows (BT, SDR noise)

            essid = row.get("ESSID", "").strip()
            privacy = row.get("Privacy", "").strip()
            cipher = row.get("Cipher", "").strip()
            auth_raw = row.get("Authentication", "").strip()
            power = row.get("Power", "").strip()
            wps = row.get("WPS", "").strip()

            auth_label = _build_auth_label(privacy, auth_raw)
            vuln = _build_vulns(privacy, auth_raw, cipher, wps)
            vendor = lookup_vendor(bssid)

            live_aps[bssid] = {
                "bssid": bssid, "essid": essid, "channel": channel,
                "privacy": auth_label, "power": power, "vendor": vendor,
                "vulnerabilities": vuln,
            }
            save_recon_ap(bssid, essid, channel, auth_label, power, vendor, vuln)

    if len(client_lines) >= 2:
        reader = csv.DictReader(client_lines, skipinitialspace=True)
        for row in reader:
            mac = row.get("Station MAC", "").strip()
            if not mac or mac == "Station MAC":
                continue
            bssid = row.get("BSSID", "").strip()
            probes = row.get("Probed ESSIDs", "").strip()
            if bssid in live_aps and live_aps[bssid]["essid"] == "" and probes:
                live_aps[bssid]["essid"] = probes.split(",")[0]
            live_clients[mac] = {"mac": mac, "associated_bssid": bssid, "probes": probes}

    return True


async def run_recon(interface: str, band: str = "dual", duration: int = 0) -> None:
    header("Passive Reconnaissance")
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    mon_iface = await start_monitor_mode(interface)
    ok(f"Monitor mode active on {mon_iface}")

    band_args = {"2": ["--band", "bg"], "5": ["--band", "a"]}.get(band, ["--band", "abg"])
    cmd = ["sudo", "airodump-ng", "--output-format", "csv",
           "--write", str(CSV_PREFIX), "--write-interval", "1"] + band_args + [mon_iface]

    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(proc)

    csv_path = str(CSV_PREFIX) + "-01.csv"
    start_time = time.time()
    info(f"Scanning ({'unlimited — Ctrl+C to stop' if duration == 0 else f'{duration}s'})...")
    info("Click is not available here, but the BSSID/SSID/channel of the strongest AP is shown each refresh for easy copy.\n")

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                changed = False
                if os.path.exists(csv_path):
                    changed = _parse_csv(csv_path)
                if changed:
                    group = Group(aps_table(live_aps), clients_table(live_clients))
                    live.update(group)
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await proc.wait()
            except Exception:
                pass
        await stop_monitor_mode(mon_iface)
        ok(f"Scan stopped. {len(live_aps)} APs / {len(live_clients)} clients discovered this session.")
        info("Full history (all-time) is saved to the SQLite DB — see `wpx.py history --recon`.")
