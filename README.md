# VLESS/REALITY Traffic Detector

A network security tool for detecting VLESS/REALITY proxy protocol traffic on your network. It captures TLS handshakes, identifies TLS 1.3 connections, and uses replay-based probe analysis to determine whether a server is running a VLESS/REALITY proxy.

## How It Works

```
Network Interface
    │  Scapy packet capture
    ▼
TLS ClientHello / ServerHello detection
    │  TCP stream reassembly
    ▼
TLS 1.3 filter (version 0x0304)
    │  Skip: LAN IPs, CN IPs (GeoIP), excluded SNIs
    ▼
Replay-based probe confirmation (3 rounds)
    │  Send captured ClientHello with original vs randomized session_id
    │  Compare server responses to probe payloads
    ▼
Detection result
    │  Consistent difference → VLESS/REALITY detected → auto-blacklist (24h)
    │  15 consecutive non-detections → auto-whitelist (24h)
    ▼
GUI log output + persisted blacklist/whitelist
```

**Detection Principle**: VLESS/REALITY servers relay the real destination server's TLS certificate but handle the encrypted tunnel differently. When the same ClientHello is replayed with a randomized `legacy_session_id`, a genuine TLS server responds identically, while a VLESS proxy responds differently (it cannot decrypt the replayed session). This behavioral difference is the detection signal.

## Features

- **GUI Interface** — tkinter-based GUI with real-time log, probe status panel, and filter controls
- **GeoIP Filtering** — Skips Chinese IPs using V2Ray/Xray `geoip.dat` (auto-generates binary cache)
- **Multi-Probe Sets** — Load multiple probe files for parallel detection
- **Auto Whitelist/Blacklist** — Persisted 24-hour lists with configurable thresholds
- **LAN Exclusion** — Automatically skips private/reserved IP ranges
- **VPN Bypass** — Binds probe sockets to interface IP to bypass TUN/VPN routing

## Prerequisites

### System Requirements

- **OS**: Windows 10/11
- **Python**: 3.8+
- **Npcap**: [https://npcap.com/](https://npcap.com/) — install with **"WinPcap API-compatible Mode"** checked
- **GeoIP Data**: `geoip.dat` from [V2Ray/Xray geoip releases](https://github.com/v2fly/geoip/releases), placed in the project root directory

### Python Dependencies

```
scapy>=2.5.0
```

> **Note**: `tkinter` is included with standard Python distributions on Windows. If it's missing, reinstall Python with the "tcl/tk" option enabled.

## Manual Run (from source)

### 1. Install dependencies

```bash
pip install scapy>=2.5.0
```

### 2. Prepare GeoIP data

Download `geoip.dat` from [v2fly/geoip releases](https://github.com/v2fly/geoip/releases) and place it in the project directory. The CN IP cache (`.cn_ip_cache.bin`) will be auto-generated on first run.

To manually regenerate the cache:

```bash
python gen_geo_cache.py
```

### 3. Prepare probe files

The project includes two probe files:

| File | Description |
|------|-------------|
| `characteristic_original.txt` | CCS/AppData probes — tests with invalid versions and oversized records |
| `characteristic_alert.txt` | TLS Alert probes — tests with various alert levels and descriptions |

These are loaded automatically on startup. You can also load custom probe files via the GUI.

### 4. Run

```bash
python main.py
```

Or directly:

```bash
python vless_detector.py
```

> **Note**: On Windows, you may need to run as Administrator for raw packet capture to work with Npcap.

### 5. Using the GUI

1. Select the network interface from the dropdown
2. Load probe file(s) if not auto-loaded (click "Load...")
3. Configure log filters (ClientHello, ServerHello, Detections, Skip)
4. Toggle "Exclude LAN IPs" as needed
5. Click **"Start Capture"** to begin sniffing

### Troubleshooting: Finding Your Network Interface

The GUI maps Npcap interface GUIDs to friendly Windows adapter names. If you need to manually identify which interface to use, run this in PowerShell:

```powershell
Get-NetAdapter | Select-Object Name, InterfaceGuid
```

Example output:

```
Name          InterfaceGuid
----          -------------
Ethernet      {B1234567-ABCD-1234-EF56-789012345678}
Wi-Fi         {C9876543-DCBA-4321-FE65-098765432109}
```

The GUI dropdown shows interfaces in the format `[Status] Name (GUID:xxxxxxxx...)`. Match the GUID prefix to identify the correct adapter.

## Run as Packaged EXE

Download the pre-built `.exe` from the [Releases](../../releases) page. All dependencies are bundled — just ensure **Npcap** is installed and `geoip.dat` is in the same directory as the executable.

```bash
# Place these files together:
#   Reality-detector.exe
#   geoip.dat
#   characteristic_original.txt
#   characteristic_alert.txt

Reality-detector.exe
```

## Configuration Files

| File | Format | Description |
|------|--------|-------------|
| `.blacklist.json` | JSON | Auto-generated — detected VLESS connections (24h expiry) |
| `.whitelist.json` | JSON | Auto-generated — confirmed non-VLESS servers (24h expiry) |
| `characteristic_original.txt` | Hex text | Probe payloads (one per line, `#` for comments) |
| `characteristic_alert.txt` | Hex text | Alert-based probe payloads |

## Key Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `MAX_STREAMS` | 1024 | Maximum concurrent TCP streams tracked |
| `REPLAY_TIMEOUT_MS` | 3000 | Timeout for replay connection (ms) |
| `PROBE_OBSERVE_TIMEOUT_MS` | 4000 | Timeout for probe response observation (ms) |
| `REQUIRED_CONFIRMATION_ROUNDS` | 3 | Consecutive matching rounds needed for detection |
| `PROBE_COOLDOWN_SEC` | 5 | Cooldown between probe batches (seconds) |
| `WHITELIST_FAIL_THRESHOLD` | 15 | Consecutive non-detections before auto-whitelist |

## Project Structure

```
├── main.py                        # Entry point (PyInstaller compatible)
├── vless_detector.py              # Core detection engine + GUI
├── geo_matcher.py                 # CN IP range matcher (binary search)
├── gen_geo_cache.py               # Builds .cn_ip_cache.bin from geoip.dat
├── requirements.txt               # Python dependencies
├── characteristic_original.txt    # Probe payload set (CCS/AppData)
├── characteristic_alert.txt       # Probe payload set (TLS Alert)
├── geoip.dat                      # V2Ray/Xray GeoIP database (not included)
└── .cn_ip_cache.bin               # Auto-generated CN IP cache (not included)
```

## License

This project is provided as-is for network security research and educational purposes.
