<p align="center">
  <img src="./assets/banner.svg" alt="SafeStay — Hidden Camera Scanner for Airbnbs and rentals" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Cuzeth/airbnb-safety-tools/releases"><img src="https://img.shields.io/github/v/release/Cuzeth/airbnb-safety-tools?color=38BDF8&label=release&style=for-the-badge" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-1E293B?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/distribution-single%20binary-38BDF8?style=for-the-badge" alt="Single-binary install">
</p>

> ## Important
>
> SafeStay is licensed under the [MIT License](./LICENSE). The MIT license's "AS IS" and no-liability clauses govern your use of the software.
>
> Network scanning, port scanning, and the techniques used by this tool may be illegal, regulated, or restricted under the laws of your jurisdiction and the terms of service of the network you are connected to. You alone are responsible for confirming that you have lawful authorization to scan, before you scan.
>
> Nothing in this software, this README, the in-app guide, or the exported report is legal advice. If you believe a crime has been committed, contact local law enforcement and a licensed attorney — not this tool.
>
> SafeStay is not affiliated with Airbnb, Vrbo, any hotel chain, or any camera vendor. Vendor names appear as technical references only.
>
> The author does not condone, encourage, or recommend running this tool against any network, device, host, platform, or person. See [DISCLAIMER.md](./DISCLAIMER.md) for the full informational notice, including a data-handling summary.

---

A terminal-based hidden-camera scanner for Airbnbs, hotels, and short-term rentals.

It scans the local WiFi network, identifies devices by manufacturer, probes camera-specific ports, and flags suspicious devices with risk levels. It also ships an in-app physical-check guide for the cameras a network scan **cannot** detect (4G/SIM cameras, SD-card recorders, devices on a separate VLAN), plus a step-by-step "what to do if you found something" reference you can read from your phone.

## Install

### One-liner (macOS & Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/Cuzeth/airbnb-safety-tools/main/install.sh | bash
```

This downloads the right binary for your platform into `~/.local/bin`, verifies its SHA-256 checksum against the signed `checksums.txt` published alongside the release, and never asks for sudo. Always inspect a piped-curl install script before running it — you can read this one [here](./install.sh).

### Manual download

Grab the latest binary for your platform from [Releases](https://github.com/Cuzeth/airbnb-safety-tools/releases). Each release ships a `checksums.txt` file you can verify the binary against:

```bash
# macOS (Apple Silicon)
curl -L -o safestay https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/safestay-darwin-arm64
curl -L -o checksums.txt https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/checksums.txt
shasum -a 256 -c <(grep safestay-darwin-arm64 checksums.txt)
chmod +x safestay

# macOS (Intel)
curl -L -o safestay https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/safestay-darwin-amd64

# Linux (x86_64)
curl -L -o safestay https://github.com/Cuzeth/airbnb-safety-tools/releases/latest/download/safestay-linux-amd64
```

### Build from source

Requires Go 1.26+.

```bash
git clone https://github.com/Cuzeth/airbnb-safety-tools.git
cd airbnb-safety-tools
make build
```

## Can't or don't want to use a terminal?

A network scan is one detection method. If you cannot install the tool, the physical sweep below catches a different class of threat and can be done from a phone. The four points below are common observations from publicly available safety reporting, not instructions from this project:

1. Hidden cameras are most commonly found in smoke detectors, alarm clocks, USB chargers, picture frames, and air purifiers near beds or showers. A tiny pinhole lens or unusual placement angle is the usual visual tell.
2. In a dark room, a flashlight slowly swept across surfaces will reflect off a camera lens as a sharp, repeatable glint that is different from glass or metal reflection.
3. The phone's front-facing camera (not the rear — most rear cameras filter IR) can see the IR LEDs of night-vision cameras as faint purple/white dots that are otherwise invisible to the eye.
4. An object with an unusual extra power cable or a small antenna stub is sometimes a 4G/LTE camera that bypasses WiFi entirely. SafeStay cannot see those over the network.

Per Airbnb's published guidance, guests who believe a hidden camera has been concealed are directed to contact local police and to file with the [Airbnb Resolution Center](https://www.airbnb.com/help/article/3061), typically within 72 hours of discovery. Personal-safety decisions and legal options depend on jurisdiction and circumstance; the above is general information, not advice. See [DISCLAIMER.md](./DISCLAIMER.md).

The same content is available inside the tool — press `?` at any time.

## Usage

For best results, run with `sudo` (so the raw-ICMP probe in the discovery phase can actually send packets — more devices end up in the ARP cache as a result):

```bash
sudo safestay
```

Without sudo, the discovery phase falls back to TCP/UDP probes only. It still works on most networks but tends to miss devices that ignore those probes:

```bash
safestay
```

Print the full informational notice:

```bash
safestay --disclaimer
```

### Controls

| Key | Action |
|-----|--------|
| `s` | Start network scan |
| `e` | Export a report (HTML + JSON) including the physical-check guide |
| `o` | Open selected device's web interface in browser |
| `1`–`9` | Select a port by number |
| `?` | Open the safety guide — physical check + what to do if you found something |
| `Esc` | Close the safety guide |
| `Tab` | Switch focus between device list and port detail panel |
| `j`/`k` or arrows | Navigate up/down |
| `PgUp`/`PgDn` | Scroll by page |
| `g`/`G` | Jump to top/bottom |
| `q` | Quit |

## How the network scan works

1. **Network discovery** — ARP scan (more complete when run with sudo) or unprivileged TCP/UDP probing finds devices on the local /24 subnet. The local IP is detected by enumerating network interfaces; no external host is contacted.
2. **Reliability assessment** — If only your own device and the router show up, SafeStay assumes the network is using AP/client isolation and warns you that the scan results below are not meaningful on their own.
3. **Vendor lookup** — Identifies manufacturers from a curated 150+ MAC OUI table for known camera brands, plus a 38K-entry fallback OUI table derived from the IEEE MA-L registry.
4. **Port scanning** — Probes 30 camera-specific ports (RTSP, ONVIF, vendor SDKs, Tuya P2P, MQTT-TLS, debug backdoors). See "Ports scanned" below.
5. **Risk assessment** — Combines vendor + open-port pattern into a risk level. The model is intentionally biased toward false positives for **unknown** vendors that respond on camera ports — that's the modern hostile-host profile (unbranded Tuya/ESP32 modules with random MACs).
6. **Browser integration** — Press `o` on any flagged device to open its admin panel.
7. **Reporting** — Press `e` for a self-contained HTML report **and** a sibling JSON file that include the device list, the physical-check guide, the "what to do if you found something" reference, and the informational notice. The headline card is screenshot-friendly.

Vendor labels in the report and detail panel are derived from MAC OUI lookup and should be read as "MAC OUI suggests X," not as a confirmed identification. MAC addresses can be spoofed; OUI assignments can be reused after revocation; aggregated databases drift.

## What this tool CANNOT see

A clean network scan is not a guarantee. Pair every scan with the physical check (press `?`):

- **4G/LTE cameras** carry their own SIM and bypass the host network entirely
- **AP / client isolation** hides every other device on the network from any scanner
- **SD-card-only recorders** never go online — they cannot be detected over the network
- **Modern unbranded cameras** run stock Tuya/ESP32/Anyka firmware with random MACs that don't appear in any vendor database
- **Cameras over Bluetooth, Zigbee, or proprietary RF** are out of scope

## Ports scanned

| Port | Protocol | Description |
|------|----------|-------------|
| 23 | Telnet | Debug/backdoor on cheap cameras |
| 80, 81, 443, 8080, 8443 | HTTP(S) | Camera web admin panels |
| 554 | RTSP | Standard video streaming (all IP cameras) |
| 1935 | RTMP | Live video streaming |
| 2000, 3702 | ONVIF / WS-Discovery | Camera network discovery |
| 3478 | STUN/TURN | WebRTC NAT traversal for cloud cameras |
| 5000, 5001 | NAS / Surveillance | Synology Surveillance Station |
| 6667 | Tuya-Discovery | Tuya Smart device discovery (unbranded cameras) |
| 6668, 6669 | Tuya/Wyze-P2P | Tuya local control and Wyze TUTK P2P |
| 8000, 8200 | Hikvision-SDK | Hikvision iVMS management |
| 8091 | Tianshitong/TOPSEE | Proprietary data channel on TOPSEE-branded cameras |
| 8554, 10554 | RTSP-Alt | Alternate RTSP — common on cheap WIFICAM-type hidden cameras |
| 8600 | TUTK-P2P | ThroughTek Kalay P2P relay (50M+ IoT devices) |
| 8883 | MQTT-TLS | Cloud channel for Tuya / Smart Life / ESP32 devices |
| 8899 | ONVIF/XMEye | Xiongmai/V380 ONVIF and basic web interface |
| 9000 | Camera-Mgmt | Secondary management / ONVIF on various brands |
| 9527 | XM-Console | Xiongmai debug backdoor |
| 32100 | CS2/PPPP | Primary port for LookCam / V380 / VRCAM hidden spy cameras |
| 34567 | XMEye | Budget IP camera protocol |
| 37777 / 37778 | Dahua-TCP/UDP | Dahua and Lorex camera control / video data |

The authoritative list lives in [internal/model/ports.go](internal/model/ports.go).

## Known camera brands detected

**Via MAC OUI:** Hikvision (81 prefixes), Dahua (27), Ring (12), Wyze (6), Arlo (6), Amcrest (4), Axis, Foscam, Reolink, Vivotek, Uniview, Hanwha/Wisenet, FLIR, Xiongmai/XMEye, Ubiquiti/UniFi, TP-Link/Tapo, Nest.

**Via vendor-name matching:** all the above plus Lorex, Swann, Eufy/Anker, Jovision, Tuya, Shelly, Espressif, Anyka, Ingenic, Goke.

Vendor names are listed strictly as technical references — they are not accusations, claims, or recommendations. Major consumer brands (Ring, Nest, Wyze, Arlo, Eufy, Tapo) are still flagged HIGH so guests know they exist, with a note that Airbnb requires hosts to disclose every camera in the listing.

## Reporting issues / contributing

Bug reports and detection-pattern contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: do not file public issues — see [SECURITY.md](./SECURITY.md).

Issue tracker: <https://github.com/Cuzeth/airbnb-safety-tools/issues>.

## License, attribution, disclaimer

- [LICENSE](./LICENSE) — MIT.
- [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) — attributions for redistributed third-party code and data.
- [DISCLAIMER.md](./DISCLAIMER.md) — informational notice, including data handling.

The short version: **AS IS, no warranty, no liability (per MIT). Not legal advice. Use at your own risk. Authorization is your responsibility. If unsure, do not run it.**
