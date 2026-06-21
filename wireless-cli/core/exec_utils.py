import asyncio
import re
import subprocess
from typing import List, Optional

# Whitelist of binaries that can be executed
ALLOWED_BINARIES = {
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "hostapd", "hostapd-wpe", "hostapd-mana",
    "dnsmasq", "hashcat", "hcxdumptool", "hcxpcapngtool",
    "bully", "reaver", "pixiewps",
    "mitmproxy", "mitmdump", "mitmweb",
    "openssl", "kill", "rfkill", "iw", "ip", "iptables",
    "tshark", "tcpdump", "systemctl", "pkill", "echo", "tee",
    "python3", "macchanger", "eapmd5pass", "asleap",
    "iw", "hcxpcapngtool", "hashcat",
    "sysctl", "chmod", "sudo", "chown"  # for system setup
}

def validate_mac(mac: str) -> bool:
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def validate_channel(ch: str) -> bool:
    return ch.isdigit() and 1 <= int(ch) <= 165

async def run_command(cmd: List[str], timeout: Optional[int] = None) -> str:
    """
    Execute a command asynchronously with shell=False.
    cmd must be a list with the first element an allowed binary.
    """
    if not cmd or cmd[0] not in ALLOWED_BINARIES:
        raise ValueError(f"Binary not allowed or empty command: {cmd[0] if cmd else 'None'}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}")

    if process.returncode != 0:
        error_msg = stderr.decode(errors='replace').strip()
        raise RuntimeError(f"Command failed (exit {process.returncode}): {error_msg}")
    return stdout.decode(errors='replace')


async def spawn_with_retry(
    cmd: List[str],
    check_seconds: float = 2.0,
    max_attempts: int = 2,
    retry_delay: float = 2.0,
    label: str = "process",
):
    """Spawn a long-running daemon (hostapd / hostapd-wpe / hostapd-mana, etc.)
    and verify it's still alive after `check_seconds`. If it died immediately
    — common on the first attempt if `airmon-ng check kill` hadn't fully
    released the interface yet, or a stale process is still holding it —
    wait `retry_delay` and try again, up to `max_attempts` total.

    Returns (process, success: bool, diagnostic_output_on_failure: str).
    The caller is responsible for calling track_process() on the returned
    process if it succeeds.
    """
    import sys
    last_output = ""
    for attempt in range(1, max_attempts + 1):
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        await asyncio.sleep(check_seconds)

        if proc.returncode is None:
            return proc, True, ""  # still running after the check window — success

        # Died immediately — capture BOTH stdout and stderr for diagnostics.
        # FIX: some daemons (e.g. hostapd-wpe) write their actual fatal
        # error output to stdout, not stderr — capturing stderr alone
        # produced an empty, useless diagnostic on failure.
        try:
            stdout_bytes = await asyncio.wait_for(proc.stdout.read(), timeout=1)
            stderr_bytes = await asyncio.wait_for(proc.stderr.read(), timeout=1)
            combined = (stdout_bytes + stderr_bytes).decode(errors="replace").strip()
            if combined:
                last_output = combined
        except Exception:
            pass

        if attempt < max_attempts:
            print(f"[!] {label} exited immediately (attempt {attempt}/{max_attempts}), "
                  f"retrying in {retry_delay}s...", file=sys.stderr)
            await asyncio.sleep(retry_delay)

    return proc, False, last_output
