from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DeviceCategory(Enum):
    CAMERA = "Camera/DVR"
    SMART_SPEAKER = "Smart Speaker"
    SMART_HOME = "Smart Home Hub"
    ROUTER = "Router/AP"
    PHONE = "Phone/Tablet"
    COMPUTER = "Computer"
    TV = "Smart TV"
    IOT_GENERIC = "IoT Device"
    UNKNOWN = "Unknown"


@dataclass
class PortInfo:
    """Detailed information about an open port."""
    port: int
    protocol: str          # e.g. "RTSP", "HTTP", "Dahua"
    description: str       # Human-readable explanation
    risk: RiskLevel        # How suspicious this port is
    web_openable: bool     # Can we open this in a browser?
    url_scheme: str = ""   # "http", "https", "rtsp", or "" if not openable

    @property
    def url_for(self) -> str | None:
        """Return a URL template (needs IP substitution) or None."""
        if not self.web_openable:
            return None
        return f"{self.url_scheme}://{{ip}}:{self.port}/"


# Master port database with detailed descriptions.
# Sources:
#   - https://nickdu.com/?p=782 (camera port reference)
#   - https://www.unifore.net/ip-video-surveillance/network-camera-rtsp-url-address-and-port-number.html
#   - Hikvision/Dahua/Reolink official documentation
PORT_DATABASE: dict[int, PortInfo] = {
    # ── Streaming protocols ──────────────────────────────────────────────
    554: PortInfo(
        port=554, protocol="RTSP", risk=RiskLevel.HIGH, web_openable=False,
        description="Real Time Streaming Protocol — standard video streaming port used by "
                    "virtually all IP cameras (Hikvision, Dahua, Axis, Reolink, etc.)",
    ),
    8554: PortInfo(
        port=8554, protocol="RTSP-Alt", risk=RiskLevel.HIGH, web_openable=False,
        description="Alternate RTSP port — used by Zhongwei/Shangwei cameras and some "
                    "cameras configured to avoid the standard 554",
    ),
    1935: PortInfo(
        port=1935, protocol="RTMP", risk=RiskLevel.HIGH, web_openable=False,
        description="Real Time Messaging Protocol — used for live video streaming, "
                    "common on cameras that stream to cloud services or NVRs",
    ),
    # ── Camera vendor-specific protocols ─────────────────────────────────
    37777: PortInfo(
        port=37777, protocol="Dahua-TCP", risk=RiskLevel.HIGH, web_openable=False,
        description="Dahua proprietary TCP control port — used by Dahua cameras, NVRs, "
                    "and Lorex rebadges for device management and video transport",
    ),
    37778: PortInfo(
        port=37778, protocol="Dahua-UDP", risk=RiskLevel.HIGH, web_openable=False,
        description="Dahua proprietary UDP data port — used alongside TCP/37777 for "
                    "real-time video data streaming on Dahua/Lorex devices",
    ),
    8000: PortInfo(
        port=8000, protocol="Hikvision-SDK", risk=RiskLevel.HIGH, web_openable=False,
        description="Hikvision iVMS/SDK service port — primary management protocol for "
                    "Hikvision cameras and NVRs, used by iVMS-4200 client software",
    ),
    8200: PortInfo(
        port=8200, protocol="Hikvision-SDK", risk=RiskLevel.HIGH, web_openable=False,
        description="Hikvision secondary service port — used for additional camera "
                    "management functions alongside port 8000",
    ),
    6668: PortInfo(
        port=6668, protocol="Wyze-TUTK", risk=RiskLevel.HIGH, web_openable=False,
        description="Wyze camera TUTK P2P protocol — used by Wyze Cam v1/v2/v3 for "
                    "peer-to-peer video streaming through their IoTCAM/TUTK SDK",
    ),
    6669: PortInfo(
        port=6669, protocol="Wyze-TUTK", risk=RiskLevel.HIGH, web_openable=False,
        description="Wyze camera secondary TUTK port — alternate P2P streaming port "
                    "used by Wyze devices for redundancy",
    ),
    34567: PortInfo(
        port=34567, protocol="XMEye/Xiongmai", risk=RiskLevel.HIGH, web_openable=False,
        description="Xiongmai (XMEye) proprietary protocol — extremely common on budget "
                    "unbranded IP cameras, DVRs, and NVRs from Chinese OEMs",
    ),
    # ── Web interfaces (openable in browser) ─────────────────────────────
    80: PortInfo(
        port=80, protocol="HTTP", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="http",
        description="HTTP web server — cameras expose admin panels here. Hikvision, "
                    "Dahua, Axis, Foscam, and most IP cameras have a web UI on port 80",
    ),
    443: PortInfo(
        port=443, protocol="HTTPS", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="https",
        description="HTTPS web server — encrypted version of the camera admin panel. "
                    "Used by Hikvision, Reolink, and enterprise cameras",
    ),
    8080: PortInfo(
        port=8080, protocol="HTTP-Alt", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="http",
        description="Alternate HTTP port — used when port 80 is taken. Common on cameras "
                    "behind routers, ONVIF discovery port for some brands (e.g. Tiandy)",
    ),
    8443: PortInfo(
        port=8443, protocol="HTTPS-Alt", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="https",
        description="Alternate HTTPS port — encrypted web interface on non-standard port, "
                    "used by some cameras and NVR systems for remote management",
    ),
    8899: PortInfo(
        port=8899, protocol="ONVIF/XMEye", risk=RiskLevel.HIGH, web_openable=True,
        url_scheme="http",
        description="Xiongmai/V380 ONVIF port — used for device discovery and management "
                    "on budget cameras. May expose a basic web interface",
    ),
    # ── NAS / Surveillance station ───────────────────────────────────────
    5000: PortInfo(
        port=5000, protocol="HTTP-NAS", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="http",
        description="Synology DSM / surveillance station HTTP — used by Synology NAS "
                    "running Surveillance Station, also used by some ONVIF cameras (Yoosee)",
    ),
    5001: PortInfo(
        port=5001, protocol="HTTPS-NAS", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="https",
        description="Synology DSM / surveillance station HTTPS — encrypted management "
                    "interface for Synology NAS with Surveillance Station",
    ),
    # ── P2P / NAT traversal ──────────────────────────────────────────────
    3478: PortInfo(
        port=3478, protocol="STUN/TURN", risk=RiskLevel.MEDIUM, web_openable=False,
        description="STUN/TURN for WebRTC NAT traversal — used by cameras that stream "
                    "through cloud services (Ring, Nest, Arlo) to punch through firewalls",
    ),
    # ── General camera management ────────────────────────────────────────
    9000: PortInfo(
        port=9000, protocol="Camera-Mgmt", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="http",
        description="Camera management port — used by various brands for secondary "
                    "management interfaces, API endpoints, or ONVIF services",
    ),
    # ── Additional discovery ports ───────────────────────────────────────
    2000: PortInfo(
        port=2000, protocol="ONVIF", risk=RiskLevel.MEDIUM, web_openable=False,
        description="ONVIF device discovery — used by Dragon/JVT cameras for ONVIF "
                    "device management and discovery",
    ),
    3702: PortInfo(
        port=3702, protocol="WS-Discovery", risk=RiskLevel.MEDIUM, web_openable=False,
        description="WS-Discovery / ONVIF — used by TECH/YOOSEE cameras for network "
                    "device discovery via Web Services Dynamic Discovery protocol",
    ),
    8091: PortInfo(
        port=8091, protocol="Tianshitong", risk=RiskLevel.HIGH, web_openable=False,
        description="Tianshitong/TOPSEE data port — proprietary data channel used by "
                    "TOPSEE branded IP cameras for video transport",
    ),
    # ── Hidden camera / spy camera ports ─────────────────────────────────
    # These ports are critical for detecting cheap hidden cameras that don't
    # use brand-name OUIs. Sources:
    #   - https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html
    #   - Warwick University "Spying on the Spy" (Herodotou & Hao, 2023)
    #   - SEC Consult Xiongmai advisory
    32100: PortInfo(
        port=32100, protocol="CS2/PPPP", risk=RiskLevel.HIGH, web_openable=False,
        description="CS2 Network P2P protocol (PPPP) — the primary port used by hidden "
                    "spy cameras (LookCam, V380, VRCAM). Uses UDP hole-punching for NAT "
                    "traversal. A response on this port is a very strong indicator of a "
                    "hidden camera. Common on Anyka AK3918-based modules",
    ),
    10554: PortInfo(
        port=10554, protocol="RTSP-Alt", risk=RiskLevel.HIGH, web_openable=False,
        description="Alternate RTSP port — commonly used by cheap WIFICAM-type hidden "
                    "cameras and GoAhead-based firmware. Often unauthenticated, allowing "
                    "direct video stream access without credentials",
    ),
    23: PortInfo(
        port=23, protocol="Telnet", risk=RiskLevel.HIGH, web_openable=False,
        description="Telnet — debug/backdoor access left enabled on many cheap Chinese "
                    "cameras. Indicates a low-quality IoT device with poor security. "
                    "Common default credentials: root/xmhdipc, root/xc3511, root/123456",
    ),
    9527: PortInfo(
        port=9527, protocol="XM-Console", risk=RiskLevel.HIGH, web_openable=False,
        description="Xiongmai debug console — telnet-like backdoor on Xiongmai/XMEye "
                    "cameras and DVRs. Allows remote command execution. Strong indicator "
                    "of a cheap surveillance device",
    ),
    81: PortInfo(
        port=81, protocol="HTTP-Alt", risk=RiskLevel.MEDIUM, web_openable=True,
        url_scheme="http",
        description="Alternate HTTP port — very common on cheap IP cameras that use port "
                    "81 instead of 80 for their web interface. Check for GoAhead server "
                    "or camera-specific paths (/system.ini, /snapshot.jpg)",
    ),
    # ── Additional P2P / cloud camera ports ──────────────────────────────
    8600: PortInfo(
        port=8600, protocol="TUTK-P2P", risk=RiskLevel.HIGH, web_openable=False,
        description="ThroughTek TUTK P2P relay — used by 50M+ IoT devices including "
                    "many hidden cameras. Part of the Kalay P2P platform that enables "
                    "cloud streaming without exposing local RTSP",
    ),
}

# Ordered list of ports to scan (derived from database)
CAMERA_PORTS = sorted(PORT_DATABASE.keys())


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    category: DeviceCategory = DeviceCategory.UNKNOWN
    risk_reasons: list[str] = field(default_factory=list)
    scan_complete: bool = False

    def get_port_info(self, port: int) -> PortInfo | None:
        """Get detailed info for a specific open port."""
        return PORT_DATABASE.get(port)

    def get_openable_ports(self) -> list[tuple[int, str]]:
        """Return list of (port, url) for ports that can be opened in a browser."""
        result = []
        for port in self.open_ports:
            info = PORT_DATABASE.get(port)
            if info and info.web_openable and info.url_for:
                result.append((port, info.url_for.format(ip=self.ip)))
        return result
