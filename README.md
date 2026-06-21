# WPX - Wireless Security Assessment Framework

WPX is a Python-based wireless security assessment framework designed for authorized Wi-Fi security testing, security research, and OSWP/PEN-210 lab environments.

The project provides a unified command-line interface that orchestrates industry-standard wireless security tools while adding workflow automation, interface management, result tracking, reporting, and operational safety features.

---

## Overview

WPX was built to simplify wireless security assessments by combining multiple Wi-Fi testing techniques into a single modular framework.

Instead of manually managing monitor mode interfaces, capture files, cracking workflows, and cleanup operations, WPX automates the process through a structured CLI architecture.

The framework focuses on:

* Wireless reconnaissance
* WPA/WPA2 handshake collection
* PMKID capture workflows
* WPS assessment
* Enterprise wireless testing
* Wireless protocol assessment
* Result persistence and reporting
* Interface lifecycle management

---

## Key Features

### Wireless Reconnaissance

* Access Point discovery
* Client enumeration
* Channel identification
* Encryption detection
* Vendor (OUI) lookup
* Live monitoring interface

### Assessment Modules

* WPA/WPA2 Handshake Capture
* PMKID Collection
* WPS Assessment
* WEP Analysis
* Enterprise Wi-Fi Credential Testing
* EAP Authentication Monitoring
* KRACK Assessment Support
* OWE Evaluation
* Wireless Client Discovery

### Operational Features

* Automatic monitor mode management
* Interface capability validation
* Process tracking and cleanup
* SQLite-based result storage
* Historical assessment records
* Session reporting
* Structured CLI workflow

### Reliability Enhancements

* Automatic subprocess cleanup
* Graceful interruption handling
* Interface state restoration
* Persistent result storage
* Error handling and validation

---

## Architecture

```text
wpx.py
│
├── core/
│   ├── hardware.py
│   ├── validation.py
│   ├── report.py
│   ├── models.py
│   ├── oui_lookup.py
│   └── exec_utils.py
│
├── modules/
│   ├── recon.py
│   ├── handshake.py
│   ├── pmkid.py
│   ├── wps.py
│   ├── wep_crack.py
│   ├── enterprise.py
│   ├── eap_sniff.py
│   ├── krack.py
│   ├── owe.py
│   ├── karma.py
│   └── evil_twin.py
│
├── captures/
└── core/db/
```

---

## Technologies Used

### Programming

* Python 3

### Wireless Tooling

* Aircrack-ng Suite
* HCXTools
* Hashcat
* Bully
* Hostapd-WPE
* Hostapd-MANA
* EAPMD5Pass
* Asleap

### Data Storage

* SQLite

### Linux Environment

* Kali Linux
* Monitor Mode Wireless Adapters
* Packet Injection Capable Hardware

---

## Engineering Highlights

### Modular Design

Each wireless testing capability is implemented as an independent module while sharing common validation, reporting, hardware management, and database functionality.

### Persistent Data Layer

Assessment results and reconnaissance history are stored in SQLite, allowing historical review of previous engagements.

### Hardware Abstraction

The framework automatically:

* Detects wireless interfaces
* Validates capabilities
* Tracks monitor mode status
* Restores interface state after execution

### Process Management

Every spawned subprocess is tracked and automatically terminated during cleanup operations to prevent orphaned processes and unstable wireless interface states.

---

## Example Capabilities

### Reconnaissance

```bash
sudo python3 wpx.py recon --iface wlan0
```

### Handshake Collection

```bash
sudo python3 wpx.py handshake \
    --iface wlan0 \
    --bssid TARGET_BSSID \
    --channel 6
```

### PMKID Collection

```bash
sudo python3 wpx.py pmkid \
    --iface wlan0 \
    --bssid TARGET_BSSID
```

### Historical Results

```bash
sudo python3 wpx.py history
```

---

## Security Notice

This framework is intended exclusively for:

* Authorized security assessments
* Personal lab environments
* Wireless security education
* Research and training

Users are responsible for complying with all applicable laws, regulations, and authorization requirements before performing any wireless security testing.

---

## Resume Project Value

This project demonstrates:

* Python software engineering
* Security tool development
* Linux systems programming
* Process orchestration
* Database integration
* Modular application architecture
* Wireless security knowledge
* CLI framework design
* Error handling and operational safety engineering

The project was developed as a practical wireless security automation framework and learning platform for advanced wireless security concepts.
