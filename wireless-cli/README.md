# wpx — Wireless Pentesting CLI Toolkit

A self-hosted command-line toolkit for wireless security testing on your
own hardware. Built for OSWP / PEN-210 study. No web server, no browser —
runs directly in your Kali terminal.

## Requirements

- Kali Linux (or any distro with the aircrack-ng suite, hostapd-wpe,
  hostapd-mana, hcxtools, bully, hashcat, asleap, eapmd5pass installed)
- A wireless NIC capable of monitor mode + packet injection (two NICs
  recommended for the `handshake` module's dual-NIC mode)
- Python 3.9+
- Root privileges (the tool checks and exits if not run as root)

## Setup

```bash
cd wireless-cli
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Place your wordlist anywhere and pass its path with `--wordlist`.

## Usage

```bash
# List interfaces and their status (monitor-capable? busy? driver?)
sudo ./venv/bin/python3 wpx.py interfaces

# Passive recon — live table of APs/clients, Ctrl+C to stop
sudo ./venv/bin/python3 wpx.py recon --iface wlan0 --band dual --duration 60

# WEP cracking
sudo ./venv/bin/python3 wpx.py wep --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6

# WPS Pixie-Dust
sudo ./venv/bin/python3 wpx.py wps --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --profile pixie

# 4-way handshake — single NIC (capture + deauth time-multiplexed)
sudo ./venv/bin/python3 wpx.py handshake --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --wordlist /path/to/wordlist.txt

# 4-way handshake — DUAL NIC (recommended if you have 2 adapters):
# wlan0 stays pure RX/capture, wlan1 handles continuous deauth TX.
# More reliable — the capture NIC never misses a frame because it's
# never interrupted to transmit.
sudo ./venv/bin/python3 wpx.py handshake --iface wlan0 --deauth-iface wlan1 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --wordlist /path/to/wordlist.txt --rules

# PMKID clientless attack
sudo ./venv/bin/python3 wpx.py pmkid --iface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --ssid MyNetwork \
    --wordlist /path/to/wordlist.txt --timeout 90

# KRACK assessment (requires krackattacks-scripts cloned into external/)
git clone https://github.com/vanhoefm/krackattacks-scripts external/krackattacks
sudo ./venv/bin/python3 wpx.py krack --iface wlan0 --ssid MyNet \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --victim-mac 11:22:33:44:55:66

# Evil Twin / captive portal credential harvest
sudo ./venv/bin/python3 wpx.py evil-twin --iface-a wlan0 \
    --ssid "Free WiFi" --channel 6 --portal-template "Airport Premium Wi-Fi"

# Rogue Enterprise AP (EAP credential harvest)
sudo ./venv/bin/python3 wpx.py enterprise --iface wlan0 \
    --ssid "CorpNet" --channel 6 --wordlist /path/to/wordlist.txt

# EAP-MD5/GTC sniffing
sudo ./venv/bin/python3 wpx.py eap-sniff --iface wlan0 --wordlist /path/to/wordlist.txt

# OWE downgrade interception (needs a 2nd NIC with internet for NAT)
sudo ./venv/bin/python3 wpx.py owe --iface-a wlan0 --iface-b wlan1 \
    --ssid "OpenNet" --channel 6

# Karma attack
sudo ./venv/bin/python3 wpx.py karma --mon-iface wlan0 --ap-iface wlan1

# View past results / recon history (persisted in SQLite, survives restarts)
sudo ./venv/bin/python3 wpx.py history
sudo ./venv/bin/python3 wpx.py history --recon
```

## How cleanup works

Every module tracks its own subprocesses and any interface it puts into
monitor mode. Pressing **Ctrl+C** at any point — mid-scan, mid-crack,
mid-attack — triggers a cleanup pass that:

1. Terminates (then force-kills if needed) every spawned subprocess
2. Runs `airmon-ng stop` on every interface that was put into monitor mode
3. Exits cleanly

No more manually typing `sudo airmon-ng stop wlan0mon` after a crash —
this is automatic and runs even on a hard interrupt.

## Output / capture files

All capture files (.cap, .pcapng, .22000, .log) are written to
`captures/` in the project directory. Cracked passwords and attack
summaries are persisted to `core/db/results.db` (SQLite) — view with
`wpx.py history`.

## Module reference

| Command | Purpose |
|---|---|
| `interfaces` | List wireless NICs, driver, monitor-mode support, busy/free |
| `recon` | Live AP/client table: vendor (OUI), auth type, vulnerabilities |
| `wep` | WEP IV collection + ARP replay + aircrack-ng |
| `wps` | WPS Pixie-Dust or full PIN brute-force via bully |
| `handshake` | 4-way handshake capture (optionally dual-NIC) + crack |
| `pmkid` | Clientless PMKID capture (hcxdumptool) + crack (hashcat) |
| `krack` | KRACK vulnerability test (requires krackattacks-scripts) |
| `evil-twin` | Rogue AP + captive portal credential harvest |
| `enterprise` | Rogue Enterprise AP (hostapd-wpe) EAP credential harvest |
| `eap-sniff` | Passive EAP-MD5/GTC credential sniffing |
| `owe` | OWE/Enhanced-Open downgrade interception |
| `karma` | Responds to client probe requests (PNL manipulation) |
| `history` | View past attack results or recon history (SQLite) |
