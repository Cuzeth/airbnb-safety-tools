# SafeStay Scanner

> **Disclaimer:** This tool is intended for personal safety use only — to check for hidden cameras in spaces you are staying in (your Airbnb, hotel room, rental, etc.). Do not run this on networks you do not have authorization to scan. Unauthorized network scanning may violate local laws and terms of service. I do not condone or take responsibility for any misuse of this tool.

Network scanner TUI to detect hidden cameras and suspicious devices at Airbnbs, hotels, and rentals.

Scans the local WiFi network, identifies devices by manufacturer, checks for camera-specific ports (RTSP, etc.), and flags suspicious devices with risk levels.

## Prerequisites

- **Python 3.10+**
- **nmap**: `brew install nmap`

## Install

```bash
cd airbnb-safety-tools
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

## Usage

For best results, run with `sudo` (enables ARP scanning which finds more devices):

```bash
sudo .venv/bin/python -m scanner
```

Without sudo (uses nmap ping scan fallback):

```bash
python -m scanner
```

### Controls

| Key | Action |
|-----|--------|
| `s` | Start network scan |
| `o` | Open selected device's web interface in browser |
| `q` | Quit |
| Arrow keys | Navigate device list |

## How It Works

1. **Network Discovery** - ARP scan (sudo) or nmap ping scan to find all devices on the local /24 subnet
2. **Vendor Lookup** - Identifies device manufacturers from MAC address OUI database (150+ IEEE-verified prefixes)
3. **Port Scanning** - Checks 20+ camera-specific ports with detailed protocol identification
4. **Risk Assessment** - Combines manufacturer + open ports into risk levels:
   - **HIGH** (red): Known camera manufacturer or camera streaming ports detected
   - **MEDIUM** (yellow): IoT/smart home device or suspicious ports
   - **LOW** (green): Normal device (computer, phone, router)
5. **Port Details** - Each open port shows protocol name, full description, and risk level
6. **Browser Integration** - Press `o` to open a device's web interface (HTTP/HTTPS ports) directly in your browser

## Ports Scanned

| Port | Protocol | Description |
|------|----------|-------------|
| 554 | RTSP | Standard video streaming (all IP cameras) |
| 8554 | RTSP-Alt | Alternate RTSP |
| 1935 | RTMP | Live video streaming |
| 37777 | Dahua-TCP | Dahua camera control |
| 37778 | Dahua-UDP | Dahua video data |
| 8000 | Hikvision-SDK | Hikvision iVMS management |
| 6668 | Wyze-TUTK | Wyze P2P streaming |
| 34567 | XMEye | Budget IP camera protocol |
| 80/443 | HTTP/HTTPS | Camera web admin panels |
| 8080/8443 | HTTP-Alt | Alternate web interfaces |
| 5000/5001 | NAS | Synology Surveillance Station |
| 3478 | STUN/TURN | WebRTC NAT traversal |

## Known Camera Brands Detected

**Via MAC OUI (150+ prefixes from IEEE registry):**
Hikvision (81 prefixes), Dahua (27), Ring (12), Wyze (6), Arlo (6), Amcrest (4), Axis, Foscam, Reolink, Vivotek, Uniview, Hanwha/Wisenet, FLIR, Xiongmai/XMEye, Ubiquiti/UniFi, TP-Link/Tapo, Nest

**Via vendor name matching:**
All of the above plus Lorex, Swann, Eufy/Anker, Jovision, Tuya, Shelly, Espressif

## Limitations

- Some WiFi networks use **AP isolation** which prevents devices from seeing each other
- Modern phones use **randomized MAC addresses** and will show as "Unknown"
- Devices on a separate VLAN or wired-only network won't appear
- Not all cameras are on WiFi (some use Bluetooth, cellular, or SD card recording)
