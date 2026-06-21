#!/usr/bin/env python3
"""
wpx.py — Wireless Pentesting CLI Toolkit
For OSWP/PEN-210 study and authorized wireless security testing on hardware
you own. Run with sudo on Kali Linux.

Usage examples:
    sudo python3 wpx.py interfaces
    sudo python3 wpx.py recon --iface wlan0 --band dual --duration 60
    sudo python3 wpx.py handshake --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --wordlist /path/rockyou.txt
    sudo python3 wpx.py handshake --iface wlan0 --deauth-iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6 --wordlist /path/rockyou.txt
    sudo python3 wpx.py pmkid --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --ssid MyNet --wordlist /path/rockyou.txt
    sudo python3 wpx.py wps --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --profile pixie
    sudo python3 wpx.py wep --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6
    sudo python3 wpx.py history
"""

import argparse
import asyncio
import json
import os
import shutil
import sys

if os.geteuid() != 0:
    print("This tool needs root privileges for raw socket / monitor mode access.")
    print("Re-run with: sudo python3 wpx.py ...")
    sys.exit(1)

from core.display import console, header, err, ok, info, warn, interfaces_table
from core.hardware import (
    get_available_interfaces, get_interface_capabilities,
    register_signal_cleanup, cleanup_all,
)
from core.models import init_db, get_results, get_recon_history


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wpx.py",
        description="Wireless Pentesting CLI Toolkit (OSWP/PEN-210 study)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── interfaces ─────────────────────────────────────────────────────────
    sub.add_parser("interfaces", help="List wireless interfaces and their status")

    # ── recon ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("recon", help="Passive AP/client reconnaissance")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--band", choices=["2", "5", "dual"], default="dual")
    sp.add_argument("--duration", type=int, default=0, help="seconds, 0 = run until Ctrl+C")

    # ── wep ────────────────────────────────────────────────────────────────
    sp = sub.add_parser("wep", help="WEP cracking (IV collection + aircrack-ng)")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--client-mac", default="")
    sp.add_argument("--no-arp-replay", action="store_true")
    sp.add_argument("--iv-threshold", type=int, default=40000)

    # ── wps ────────────────────────────────────────────────────────────────
    sp = sub.add_parser("wps", help="WPS Pixie-Dust / PIN brute-force")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--profile", choices=["pixie", "full"], default="pixie")
    sp.add_argument("--delay", type=int, default=5, help="seconds between PIN attempts (full brute-force only)")
    sp.add_argument("--nofcs", action="store_true", help="needed for some RTL/Realtek chipsets")

    # ── handshake ──────────────────────────────────────────────────────────
    sp = sub.add_parser("handshake", help="4-way handshake capture + crack")
    sp.add_argument("--iface", required=True, help="capture interface")
    sp.add_argument("--deauth-iface", default="", help="OPTIONAL second NIC dedicated to deauth (more reliable capture)")
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--client-mac", default="")
    sp.add_argument("--wordlist", required=True)
    sp.add_argument("--deauth-count", type=int, default=0, help="0 = continuous")
    sp.add_argument("--max-duration", type=int, default=600, help="session timeout in seconds, 0 = no limit")
    sp.add_argument("--rules", action="store_true", help="use hashcat + best64 rules instead of aircrack-ng")

    # ── pmkid ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("pmkid", help="PMKID clientless capture + crack")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--ssid", required=True)
    sp.add_argument("--wordlist", required=True)
    sp.add_argument("--timeout", type=int, default=60, help="capture window in seconds")
    sp.add_argument("--rules", action="store_true")

    # ── krack ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("krack", help="KRACK vulnerability assessment")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--ssid", required=True)
    sp.add_argument("--bssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--victim-mac", required=True)
    sp.add_argument("--psk", default="abcdefgh")
    sp.add_argument("--profile", choices=["standard", "group", "tptk", "tptk_rand", "replay_broadcast"], default="standard")
    sp.add_argument("--debug", action="store_true")

    # ── evil-twin ──────────────────────────────────────────────────────────
    sp = sub.add_parser("evil-twin", help="Rogue AP / captive portal credential harvest")
    sp.add_argument("--iface-a", required=True, help="rogue AP broadcast interface")
    sp.add_argument("--iface-b", default="", help="internet uplink (unused if no NAT desired)")
    sp.add_argument("--ssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--bssid", default="", help="spoof a specific BSSID (default: random)")
    sp.add_argument("--mode", choices=["A", "B"], default="A")
    sp.add_argument("--portal-template", default="Generic Cafe")
    sp.add_argument("--port", type=int, default=80, help="captive portal HTTP port (80 = triggers OS auto-popup; use 8080+ only if testing manually in a browser)")

    # ── enterprise ─────────────────────────────────────────────────────────
    sp = sub.add_parser("enterprise", help="Rogue Enterprise AP (EAP credential harvest)")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--ssid", required=True)
    sp.add_argument("--channel", required=True)
    sp.add_argument("--eap-type", choices=["PEAP", "TTLS"], default="PEAP")
    sp.add_argument("--cn", default="auth.company.local")
    sp.add_argument("--org", default="Corporate IT Services")
    sp.add_argument("--wordlist", required=True)
    sp.add_argument("--deauth-iface", default="")

    # ── eap-sniff ──────────────────────────────────────────────────────────
    sp = sub.add_parser("eap-sniff", help="EAP-MD5 / EAP-GTC credential sniffing")
    sp.add_argument("--iface", required=True)
    sp.add_argument("--channel", default="")
    sp.add_argument("--wordlist", default="")

    # ── owe ────────────────────────────────────────────────────────────────
    sp = sub.add_parser("owe", help="OWE / Enhanced Open downgrade interception")
    sp.add_argument("--iface-a", required=True)
    sp.add_argument("--iface-b", required=True)
    sp.add_argument("--ssid", required=True)
    sp.add_argument("--channel", required=True)

    # ── karma ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("karma", help="Karma attack (PNL manipulation)")
    sp.add_argument("--mon-iface", required=True)
    sp.add_argument("--ap-iface", required=True)
    sp.add_argument("--wordlist", default="")
    sp.add_argument("--portal-template", default="Generic Cafe")
    sp.add_argument("--stealth-mac", action="store_true")

    # ── history ────────────────────────────────────────────────────────────
    sp = sub.add_parser("history", help="Show past attack results / recon history")
    sp.add_argument("--recon", action="store_true", help="show recon AP history instead of attack results")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--json", action="store_true", help="output as JSON instead of a table")

    # ── report ─────────────────────────────────────────────────────────────
    sp = sub.add_parser("report", help="Generate a Markdown session report (results + recon history)")
    sp.add_argument("--limit", type=int, default=500)

    # ── doctor ─────────────────────────────────────────────────────────────
    sub.add_parser("doctor", help="Check that all required external tools are installed")

    return p


async def cmd_interfaces():
    header("Wireless Interfaces")
    interfaces = await get_interface_capabilities()
    if not interfaces:
        err("No wireless interfaces detected. Plug in a NIC and try again.")
        return
    console.print(interfaces_table(interfaces))


def cmd_history(args):
    from rich.table import Table
    if args.recon:
        aps = get_recon_history(limit=args.limit)
        if args.json:
            print(json.dumps(aps, indent=2))
            return
        header("Recon History (all-time)")
        if not aps:
            console.print("[dim]No recon history yet.[/dim]")
            return
        table = Table()
        for col in ["BSSID", "SSID", "Vendor", "Ch", "Auth", "First Seen", "Last Seen"]:
            table.add_column(col)
        import datetime
        for ap in aps:
            table.add_row(
                ap["bssid"], ap["essid"] or "<hidden>", ap["vendor"] or "—",
                ap["channel"], ap["privacy"],
                datetime.datetime.fromtimestamp(ap["first_seen"]).strftime("%Y-%m-%d %H:%M"),
                datetime.datetime.fromtimestamp(ap["last_seen"]).strftime("%Y-%m-%d %H:%M"),
            )
        console.print(table)
    else:
        results = get_results(limit=args.limit)
        if args.json:
            print(json.dumps(results, indent=2))
            return
        header("Attack Results History")
        if not results:
            console.print("[dim]No results yet.[/dim]")
            return
        table = Table()
        for col in ["Time", "Module", "BSSID", "SSID", "Result"]:
            table.add_column(col)
        import datetime
        for r in results:
            table.add_row(
                datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M"),
                r["module"], r["target_bssid"] or "—", r["target_ssid"] or "—", r["result"] or "—",
            )
        console.print(table)


def cmd_report(args):
    from core.report import write_report
    path = write_report(limit=args.limit)
    ok(f"Report written to: {path}")
    info(f"  {path.stat().st_size} bytes — open in any Markdown viewer or convert to PDF with pandoc:")
    console.print(f"  [cyan]pandoc {path} -o {path.with_suffix('.pdf')}[/cyan]")


# Tool -> (apt package, used-by modules) for the doctor command
REQUIRED_TOOLS = {
    "airmon-ng":    ("aircrack-ng", "recon, wep, wps, handshake, krack"),
    "airodump-ng":  ("aircrack-ng", "recon, wep, handshake"),
    "aireplay-ng":  ("aircrack-ng", "wep, handshake, krack, enterprise"),
    "aircrack-ng":  ("aircrack-ng", "wep, handshake"),
    "bully":        ("bully", "wps"),
    "hcxdumptool":  ("hcxtools", "pmkid"),
    "hcxpcapngtool":("hcxtools", "pmkid, handshake --rules"),
    "hashcat":      ("hashcat", "pmkid, handshake --rules"),
    "hostapd":      ("hostapd", "evil-twin, owe, krack"),
    "hostapd-wpe":  ("hostapd-wpe", "enterprise"),
    "hostapd-mana": ("hostapd-mana", "karma"),
    "dnsmasq":      ("dnsmasq", "evil-twin, enterprise, owe, karma"),
    "asleap":       ("asleap", "enterprise"),
    "eapmd5pass":   ("eapmd5pass", "eap-sniff"),
    "tshark":       ("tshark", "handshake, eap-sniff, owe"),
    "macchanger":   ("macchanger", "karma --stealth-mac"),
    "mitmweb":      ("mitmproxy (pip install mitmproxy)", "evil-twin --mode B"),
    "openssl":      ("openssl", "evil-twin --mode B"),
    "iw":           ("iw", "interfaces, all monitor-mode modules"),
    "python2":      ("python2", "krack"),
}


def cmd_doctor():
    header("Dependency Check")
    missing = []
    for tool, (package, used_by) in sorted(REQUIRED_TOOLS.items()):
        found = shutil.which(tool) is not None
        status = "[green]OK[/green]" if found else "[red]MISSING[/red]"
        console.print(f"  {status:20s} {tool:16s} (used by: {used_by})")
        if not found:
            missing.append((tool, package))

    console.print()
    if missing:
        warn(f"{len(missing)} tool(s) missing. Install with:")
        pkgs = sorted(set(pkg for _, pkg in missing if "pip install" not in pkg))
        if pkgs:
            console.print(f"  [cyan]sudo apt install {' '.join(pkgs)}[/cyan]")
        pip_pkgs = [pkg for _, pkg in missing if "pip install" in pkg]
        for pkg in pip_pkgs:
            console.print(f"  [cyan]{pkg.split('(')[1].rstrip(')')}[/cyan]")
    else:
        ok("All required tools found.")


async def dispatch(args) -> None:
    if args.command == "interfaces":
        await cmd_interfaces()
        return
    if args.command == "history":
        cmd_history(args)
        return
    if args.command == "report":
        cmd_report(args)
        return
    if args.command == "doctor":
        cmd_doctor()
        return

    if args.command == "recon":
        from modules.recon import run_recon
        await run_recon(args.iface, args.band, args.duration)

    elif args.command == "wep":
        from modules.wep_crack import run_wep_crack
        await run_wep_crack(args.iface, args.bssid, args.channel, args.client_mac,
                             not args.no_arp_replay, args.iv_threshold)

    elif args.command == "wps":
        from modules.wps import run_wps_attack
        await run_wps_attack(args.iface, args.bssid, args.channel, args.profile, args.delay, args.nofcs)

    elif args.command == "handshake":
        from modules.handshake import run_handshake_crack
        await run_handshake_crack(args.iface, args.bssid, args.channel, args.client_mac,
                                   args.wordlist, args.deauth_count, args.rules,
                                   args.deauth_iface, args.max_duration)

    elif args.command == "pmkid":
        from modules.pmkid import run_pmkid
        await run_pmkid(args.iface, args.bssid, args.channel, args.ssid, args.wordlist,
                         args.timeout, args.rules)

    elif args.command == "krack":
        from modules.krack import run_krack_test
        await run_krack_test(args.iface, args.ssid, args.bssid, args.channel, args.victim_mac,
                              args.psk, args.profile, args.debug)

    elif args.command == "evil-twin":
        from modules.evil_twin import run_evil_twin
        await run_evil_twin(args.iface_a, args.iface_b, args.ssid, args.channel, args.bssid,
                             args.mode, args.portal_template, args.port)

    elif args.command == "enterprise":
        from modules.enterprise import run_enterprise_attack
        await run_enterprise_attack(args.iface, args.ssid, args.channel, args.eap_type,
                                     args.cn, args.org, args.wordlist, args.deauth_iface)

    elif args.command == "eap-sniff":
        from modules.eap_sniff import run_eap_sniff
        await run_eap_sniff(args.iface, args.channel, args.wordlist)

    elif args.command == "owe":
        from modules.owe import run_owe_attack
        await run_owe_attack(args.iface_a, args.iface_b, args.ssid, args.channel)

    elif args.command == "karma":
        from modules.karma import run_karma_attack
        await run_karma_attack(args.mon_iface, args.ap_iface, args.wordlist,
                                args.portal_template, args.stealth_mac)


async def main_async(args):
    loop = asyncio.get_event_loop()
    register_signal_cleanup(loop)
    try:
        await dispatch(args)
    finally:
        await cleanup_all()


def main():
    init_db()
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
