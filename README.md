<p align="center">
  <img src="./assets/banner.svg" alt="SafeStay — Hidden Camera Scanner for Airbnbs and rentals" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Cuzeth/airbnb-safety-tools/releases"><img src="https://img.shields.io/github/v/release/Cuzeth/airbnb-safety-tools?color=38BDF8&label=release&style=for-the-badge" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-1E293B?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/distribution-single%20binary-38BDF8?style=for-the-badge" alt="Single-binary install">
</p>

> Hobby project, MIT-licensed, AS IS, no warranty, no liability. Not legal advice. Network scanning may be illegal where you are — that's on you to check before running it. If unsure, don't run it.

A terminal-based hidden-camera scanner for Airbnbs, hotels, and short-term rentals. It scans the local WiFi network, identifies devices by manufacturer, probes camera-specific ports, and flags suspicious devices.

It cannot see 4G/SIM cameras, SD-card-only recorders, devices on a separate VLAN, or networks with AP/client isolation — pair every scan with a physical check of the room.

## Install

### One-liner (macOS & Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/Cuzeth/airbnb-safety-tools/main/install.sh | bash
```

Downloads the right binary for your platform into `~/.local/bin` and verifies its SHA-256 against the `checksums.txt` from the same GitHub release. The checksum file is hosted over HTTPS but is **not** cryptographically signed. Always inspect a piped-curl install script before running it — you can read this one [here](./install.sh).

### Manual download

Grab the latest binary for your platform from [Releases](https://github.com/Cuzeth/airbnb-safety-tools/releases) and verify against `checksums.txt`:

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

## Usage

For best results, run with `sudo` (so the raw-ICMP probe in the discovery phase can actually send packets — more devices end up in the ARP cache as a result):

```bash
sudo safestay
```

Without sudo, the discovery phase falls back to TCP/UDP probes only. It still works on most networks but tends to miss devices that ignore those probes:

```bash
safestay
```

### Controls

| Key | Action |
|-----|--------|
| `s` | Start network scan |
| `e` | Export a report (HTML + JSON) |
| `o` | Open selected device's web interface in browser |
| `1`–`9` | Select a port by number |
| `?` | Open the physical-check guide |
| `Esc` | Close the safety guide |
| `Tab` | Switch focus between device list and port detail panel |
| `j`/`k` or arrows | Navigate up/down |
| `PgUp`/`PgDn` | Scroll by page |
| `g`/`G` | Jump to top/bottom |
| `q` | Quit |

## How the scan works

1. **Network discovery** — ARP scan (more complete when run with sudo) or unprivileged TCP/UDP probing finds devices on the local /24 subnet.
2. **Reliability assessment** — If only your own device and the router show up, SafeStay assumes the network is using AP/client isolation and warns you that the scan results are not meaningful on their own.
3. **Vendor lookup** — Identifies manufacturers from a curated camera-brand OUI table, plus a ~38K-entry fallback OUI table derived from the IEEE MA-L registry.
4. **Port scanning** — Probes 30 camera-specific ports (RTSP, ONVIF, vendor SDKs, Tuya P2P, MQTT-TLS, debug backdoors).
5. **Risk assessment** — Combines vendor + open-port pattern into a risk level. The model is intentionally biased toward false positives for unknown vendors that respond on camera ports — that's the modern hostile-host profile (unbranded Tuya/ESP32 modules with random MACs).
6. **Browser integration** — Press `o` on any flagged device to open its admin panel.
7. **Reporting** — Press `e` for a self-contained HTML report and a sibling JSON file.

Vendor labels are derived from MAC OUI lookup. They indicate what the OUI registry assigns the address block to — not a confirmed identification of the physical device. MAC addresses can be spoofed; OUI assignments can be reused.

## What this tool CANNOT see

A clean scan is not a guarantee. Pair every scan with a physical check:

- **4G/LTE cameras** carry their own SIM and bypass the host network entirely
- **AP / client isolation** hides every other device on the network from any scanner
- **SD-card-only recorders** never go online — they cannot be detected over the network
- **Modern unbranded cameras** run stock Tuya/ESP32/Anyka firmware with random MACs that don't appear in any vendor database
- **Cameras over Bluetooth, Zigbee, or proprietary RF** are out of scope

## Ports scanned

The authoritative list lives in [internal/model/ports.go](internal/model/ports.go).

## Reporting issues / contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: do not file public issues — see [SECURITY.md](./SECURITY.md).

Issue tracker: <https://github.com/Cuzeth/airbnb-safety-tools/issues>.

## License

[MIT](./LICENSE). See [NOTICE](./NOTICE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for redistributed third-party attributions.

AS IS, no warranty, no liability. Not legal advice. Use at your own risk.
