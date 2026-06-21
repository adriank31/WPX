"""
Hardware helpers for the CLI: interface discovery, monitor-mode lifecycle,
and a process-wide cleanup registry so Ctrl+C always leaves the system clean.
"""

import asyncio
import atexit
import os
import signal
import sys

from core.exec_utils import run_command
from core.display import info, warn, err

# ---------------------------------------------------------------------------
# Cleanup registry — every running subprocess + claimed interface is tracked
# here so a Ctrl+C (or any exit) can clean everything up, even mid-attack.
# ---------------------------------------------------------------------------
_active_processes: list = []     # list of asyncio.subprocess.Process
_active_monitor_ifaces: list = []  # list of monitor-mode iface names to restore
_cleanup_registered = False


def track_process(proc) -> None:
    _active_processes.append(proc)


def track_monitor_iface(iface: str) -> None:
    if iface not in _active_monitor_ifaces:
        _active_monitor_ifaces.append(iface)


def untrack_monitor_iface(iface: str) -> None:
    if iface in _active_monitor_ifaces:
        _active_monitor_ifaces.remove(iface)


async def cleanup_all() -> None:
    """Kill every tracked subprocess and restore every tracked monitor
    interface back to managed mode. Called on Ctrl+C and on normal exit."""
    for proc in _active_processes:
        try:
            if proc.returncode is None:
                proc.terminate()
        except Exception:
            pass
    await asyncio.sleep(0.3)
    for proc in _active_processes:
        try:
            if proc.returncode is None:
                proc.kill()
        except Exception:
            pass
    for iface in list(_active_monitor_ifaces):
        try:
            await stop_monitor_mode(iface)
        except Exception:
            pass
    _active_processes.clear()
    _active_monitor_ifaces.clear()


def register_signal_cleanup(loop) -> None:
    """Wire SIGINT/SIGTERM to a graceful async cleanup, once per process."""
    global _cleanup_registered
    if _cleanup_registered:
        return
    _cleanup_registered = True

    def _handler(*_):
        warn("Interrupted — cleaning up (restoring interfaces, killing processes)...")
        loop.create_task(_shutdown())

    async def _shutdown():
        await cleanup_all()
        info("Cleanup complete. Exiting.")
        os._exit(0)

    try:
        loop.add_signal_handler(signal.SIGINT, _handler)
        loop.add_signal_handler(signal.SIGTERM, _handler)
    except (NotImplementedError, RuntimeError):
        # Fallback for platforms without loop signal handlers
        signal.signal(signal.SIGINT, lambda *_: sys.exit(1))


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

def get_available_interfaces() -> list:
    """Managed (non-monitor) wireless interfaces, freshly scanned every call —
    so a NIC plugged in mid-session is picked up immediately."""
    ifaces = []
    for iface in os.listdir("/sys/class/net"):
        if iface.startswith(("wlan", "wlx", "wlp")) and not iface.endswith("mon"):
            ifaces.append(iface)
    return ifaces


async def _iface_mode(iface: str) -> str:
    try:
        out = await run_command(["sudo", "iw", "dev", iface, "info"])
        for line in out.splitlines():
            if "type " in line:
                return line.strip().split()[-1]
    except Exception:
        pass
    return ""


async def get_interface_capabilities() -> list:
    """Rich per-NIC status: mode, driver, monitor-mode support."""
    results = []
    ifaces = [i for i in os.listdir("/sys/class/net") if i.startswith(("wlan", "wlx", "wlp"))]

    phy_supports_monitor = {}
    try:
        iw_list = await run_command(["iw", "list"])
        current_phy = None
        in_modes_block = False
        for line in iw_list.splitlines():
            stripped = line.strip()
            if stripped.startswith("Wiphy "):
                current_phy = stripped.split()[1]
                phy_supports_monitor[current_phy] = False
                in_modes_block = False
            elif "Supported interface modes" in stripped:
                in_modes_block = True
            elif in_modes_block and stripped.startswith("*"):
                if "monitor" in stripped.lower() and current_phy:
                    phy_supports_monitor[current_phy] = True
            elif in_modes_block and not stripped.startswith("*"):
                in_modes_block = False
    except Exception:
        pass

    for iface in sorted(ifaces):
        mode = await _iface_mode(iface)
        driver = ""
        try:
            driver_link = f"/sys/class/net/{iface}/device/driver"
            if os.path.islink(driver_link):
                driver = os.path.basename(os.readlink(driver_link))
        except Exception:
            pass

        supports_monitor = None
        try:
            phy_link = f"/sys/class/net/{iface}/phy80211"
            if os.path.islink(phy_link) or os.path.exists(phy_link):
                phy_name = os.path.basename(os.path.realpath(phy_link))
                if phy_name in phy_supports_monitor:
                    supports_monitor = phy_supports_monitor[phy_name]
        except Exception:
            pass

        results.append({
            "name": iface,
            "mode": mode or "unknown",
            "driver": driver or "unknown",
            "supports_monitor": supports_monitor,
            "claimed_by": None,  # CLI runs one attack per process; n/a
        })
    return results


async def start_monitor_mode(interface: str) -> str:
    """Put *interface* into monitor mode, returning the monitor iface name.
    Tracks it for automatic cleanup on exit/Ctrl+C."""
    mode = await _iface_mode(interface)
    if mode == "monitor":
        track_monitor_iface(interface)
        return interface

    ifaces_before = set(os.listdir("/sys/class/net"))
    info(f"Enabling monitor mode on {interface}...")
    output = await run_command(["sudo", "airmon-ng", "start", interface])
    ifaces_after = set(os.listdir("/sys/class/net"))

    new_ifaces = ifaces_after - ifaces_before
    mon_candidates = sorted(i for i in new_ifaces if "mon" in i.lower())
    mon_iface = None
    if mon_candidates:
        mon_iface = mon_candidates[0]
    else:
        for line in output.splitlines():
            if "monitor mode" in line.lower():
                for token in line.replace("(", " ").replace(")", " ").split():
                    token = token.strip("[]")
                    if token in ifaces_after and token != interface:
                        mon_iface = token
                        break
        if not mon_iface:
            mon_iface = interface + "mon"

    track_monitor_iface(mon_iface)
    return mon_iface


async def stop_monitor_mode(mon_iface: str) -> None:
    try:
        await run_command(["sudo", "airmon-ng", "stop", mon_iface])
    except Exception:
        pass
    untrack_monitor_iface(mon_iface)


# ---------------------------------------------------------------------------
# GPU detection for hashcat (cached for the process lifetime)
# ---------------------------------------------------------------------------
_gpu_check_done = False
_gpu_available = False
_gpu_summary = ""


async def detect_hashcat_gpu() -> tuple:
    """Run `hashcat -I` once per process and cache the result.

    Returns (gpu_available: bool, summary: str). A device counts as a real
    GPU if its 'Type' line reports GPU; CPU-only OpenCL backends report CPU.
    """
    global _gpu_check_done, _gpu_available, _gpu_summary
    if _gpu_check_done:
        return _gpu_available, _gpu_summary

    _gpu_check_done = True
    try:
        out = await run_command(["hashcat", "-I"])
        gpu_devices, cpu_devices = [], []
        current_name = None
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("Device #") and ":" in stripped:
                current_name = stripped.split(":", 1)[1].strip()
            if stripped.startswith("Type") and ":" in stripped:
                dtype = stripped.split(":", 1)[1].strip().upper()
                if "GPU" in dtype and current_name:
                    gpu_devices.append(current_name)
                elif "CPU" in dtype and current_name:
                    cpu_devices.append(current_name)
        if gpu_devices:
            _gpu_available = True
            _gpu_summary = f"GPU detected: {', '.join(gpu_devices)}"
        elif cpu_devices:
            _gpu_available = False
            _gpu_summary = f"CPU-only OpenCL backend ({', '.join(cpu_devices)}) — hashcat will be slow"
        else:
            _gpu_available = False
            _gpu_summary = "Could not parse hashcat -I output"
    except Exception as e:
        _gpu_available = False
        _gpu_summary = f"hashcat -I failed ({e}) — assuming CPU-only"

    return _gpu_available, _gpu_summary
