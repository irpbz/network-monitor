# 🌐 Network Monitor Pro

> Real-time network monitor for Windows with per-process I/O, DPI, firewall, alerts, and a modern UI.

[![Version](https://img.shields.io/badge/version-8.0-blue.svg)](../../releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build](https://github.com/irpbz/network-monitor/actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

**[Website](https://www.artika.ir)** · **[Download Latest](../../releases/latest)** · **[Docs](../../wiki)** · **[Report a Bug](../../issues/new?template=bug_report.md)**

![Live tab](screenshots/live.png)

---

## ✨ Features

- 📊 **Live Traffic Graph** — real-time download/upload speed chart
- 🔍 **Per-Process I/O** — per-process upload/download, totals, and connection list
- 🛡️ **Smart Firewall** — block IPs, ports, or domains with one click (uses Windows Firewall)
- 🧬 **Deep Packet Inspection** — detect domains from DNS queries and TLS SNI (no decryption)
- 🚨 **Smart Alerts** — new process, unsigned process, blacklisted process, high download, possible port scan
- 📜 **Alert History** — persistent history in SQLite with severity
- ⏱ **Download Stopwatch** — timer + average speed for a download session
- 📈 **Monthly Data Quota** — track usage against a cap with 80% / 90% / 100% alerts
- 🖥 **Taskbar Overlay** — speed shown on the Windows taskbar
- 🪟 **Floating Meter** — draggable translucent mini-window with live graph
- 🎨 **Dark Mode** — Light / Dark themes
- 🌍 **GeoIP** (optional) — country lookup for remote IPs (GeoLite2)
- 💾 **PCAP Recording** — capture traffic to a `.pcap` file
- 📤 **Export** — CSV and HTML reports
- 🧩 **Filter Presets** — All / External / Blocked / Unsigned / High Traffic / Listening
- 🔎 **Search & Sort** — by name, PID, IP, or domain
- 🖱 **CLI Mode** — lightweight console monitor (`NetworkMonitorPro.exe --cli`)
- 🔄 **Built-in Update Checker** — via GitHub Releases

---

## 🚀 Installation

### For End Users

1. Download the latest `NetMonPro_Setup_x.x.exe` from [Releases](../../releases/latest).
2. Run the installer (Administrator required).
3. Install [Npcap](https://npcap.com/#download) if you want DPI and packet capture.
   - During Npcap install, keep the default options and enable
     **"Install Npcap in WinPcap API-compatible Mode"**.
4. Launch **Network Monitor Pro** from the Start Menu or desktop shortcut.

> ⚠️ **Administrator privileges are required.** Smart Firewall, DPI, and PCAP
> features need elevation. The installer and the EXE are both built with
> `uac_admin=True`, so Windows will prompt for elevation automatically.

### From Source

```cmd
git clone https://github.com/irpbz/network-monitor.git
cd network-monitor
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python net.py

Python 3.10 or newer is required (3.12 recommended).

🐛 Troubleshooting
"Npcap is not installed" / DPI does not work

Install Npcap from https://npcap.com/#download and enable
"Install Npcap in WinPcap API-compatible Mode" during setup.
