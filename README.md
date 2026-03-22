# SafeStay Scanner

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
| `q` | Quit |
| Arrow keys | Navigate device list |

## How It Works

1. **Network Discovery** - ARP scan (sudo) or nmap ping scan to find all devices on the local /24 subnet
2. **Vendor Lookup** - Identifies device manufacturers from MAC address OUI database
3. **Port Scanning** - Checks camera-specific ports (RTSP 554, Dahua 37777, Hikvision 8000, etc.)
4. **Risk Assessment** - Combines manufacturer + open ports into risk levels:
   - **HIGH** (red): Known camera manufacturer or camera streaming ports detected
   - **MEDIUM** (yellow): IoT/smart home device or suspicious ports
   - **LOW** (green): Normal device (computer, phone, router)

## Known Camera Brands Detected

Hikvision, Dahua, Wyze, Ring, Arlo, Axis, Foscam, Amcrest, Reolink, Vivotek, Uniview, Eufy, TP-Link Tapo, Nest, Lorex, Swann, and more.

## Limitations

- Some WiFi networks use **AP isolation** which prevents devices from seeing each other
- Modern phones use **randomized MAC addresses** and will show as "Unknown"
- Devices on a separate VLAN or wired-only network won't appear
- Not all cameras are on WiFi (some use Bluetooth, cellular, or SD card recording)
