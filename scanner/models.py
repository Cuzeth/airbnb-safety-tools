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


CAMERA_PORTS = [
    554,    # RTSP
    80,     # HTTP
    443,    # HTTPS
    8080,   # Alt HTTP
    8443,   # Alt HTTPS
    8554,   # Alt RTSP
    1935,   # RTMP
    5000,   # Synology / various
    5001,   # Synology SSL
    37777,  # Dahua
    37778,  # Dahua
    8000,   # Hikvision
    8200,   # Hikvision
    3478,   # STUN/TURN (WebRTC)
    6668,   # Wyze
    6669,   # Wyze
    9000,   # Various cameras
]


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
