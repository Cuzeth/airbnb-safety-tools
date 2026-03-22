"""Known camera and IoT manufacturer MAC prefix database for device fingerprinting."""

from scanner.models import DeviceCategory, RiskLevel

# MAC OUI prefixes (first 3 bytes, uppercase, colon-separated) for known camera brands.
# These get HIGH risk automatically.
CAMERA_OUI_PREFIXES: dict[str, str] = {
    # Hikvision
    "04:02:CA": "Hikvision",
    "18:68:CB": "Hikvision",
    "28:57:BE": "Hikvision",
    "2C:A5:9C": "Hikvision",
    "44:19:B6": "Hikvision",
    "4C:BD:8F": "Hikvision",
    "54:C4:15": "Hikvision",
    "64:DB:8B": "Hikvision",
    "78:F2:38": "Hikvision",
    "80:A7:C0": "Hikvision",
    "94:E1:AC": "Hikvision",
    "A4:14:37": "Hikvision",
    "AC:B7:4F": "Hikvision",
    "B4:A3:82": "Hikvision",
    "BC:AD:28": "Hikvision",
    "C0:56:E3": "Hikvision",
    "C4:2F:90": "Hikvision",
    "C8:A7:02": "Hikvision",
    "D4:43:0E": "Hikvision",
    "E4:D5:8B": "Hikvision",
    "EC:3E:09": "Hikvision",
    # Dahua
    "3C:E3:6B": "Dahua",
    "3C:EF:8C": "Dahua",
    "40:F4:FD": "Dahua",
    "4C:11:BF": "Dahua",
    "60:F9:46": "Dahua",
    "90:02:A9": "Dahua",
    "9C:14:63": "Dahua",
    "A0:BD:1D": "Dahua",
    "B0:A7:32": "Dahua",
    "D4:43:A8": "Dahua",
    "E0:50:8B": "Dahua",
    "E4:24:6C": "Dahua",
    # Wyze
    "2C:AA:8E": "Wyze",
    "7C:78:B2": "Wyze",
    "80:48:2C": "Wyze",
    "D0:3F:27": "Wyze",
    "F0:C8:8B": "Wyze",
    # Ring
    "34:3E:A4": "Ring",
    "54:E0:19": "Ring",
    "5C:47:5E": "Ring",
    "64:9A:63": "Ring",
    "90:48:6C": "Ring",
    "AC:9F:C3": "Ring",
    "CC:3B:FB": "Ring",
    # Axis Communications
    "00:40:8C": "Axis",
    "AC:CC:8E": "Axis",
    "B8:A4:4F": "Axis",
    # Foscam
    "C0:61:18": "Foscam",
    "00:0D:C5": "Foscam",
    # Amcrest
    "9C:8E:CD": "Amcrest",
    # Reolink
    "EC:71:DB": "Reolink",
    "B4:6D:83": "Reolink",
    # Vivotek
    "00:02:D1": "Vivotek",
    # Uniview
    "24:24:05": "Uniview",
    # TP-Link (Tapo cameras)
    "60:32:B1": "TP-Link/Tapo",
    "98:25:4A": "TP-Link/Tapo",
    # Eufy / Anker
    "78:8C:B5": "Eufy/Anker",
    # Arlo
    "20:3D:BD": "Arlo",
    "6C:4A:85": "Arlo",
    "9C:E6:35": "Arlo",
    # Nest (cameras specifically)
    "18:B4:30": "Nest",
    "64:16:66": "Nest",
}

# Vendor name substrings mapped to device categories.
# Matched case-insensitively against the vendor string from mac-vendor-lookup.
VENDOR_CATEGORY_MAP: dict[str, tuple[DeviceCategory, RiskLevel]] = {
    # HIGH risk - camera/surveillance companies
    "hikvision": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "dahua": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "wyze": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "ring": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "axis communications": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "foscam": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "amcrest": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "reolink": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "vivotek": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "uniview": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "arlo": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "eufy": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "anker innovations": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "nest": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "ubiquiti": (DeviceCategory.CAMERA, RiskLevel.MEDIUM),
    "hanwha": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "flir": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "lorex": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "swann": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    # MEDIUM risk - IoT / smart home
    "amazon": (DeviceCategory.SMART_SPEAKER, RiskLevel.MEDIUM),
    "google": (DeviceCategory.SMART_HOME, RiskLevel.MEDIUM),
    "apple": (DeviceCategory.PHONE, RiskLevel.LOW),
    "sonos": (DeviceCategory.SMART_SPEAKER, RiskLevel.MEDIUM),
    "tuya": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "shelly": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "espressif": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "tp-link": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "tapo": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "samsung": (DeviceCategory.TV, RiskLevel.LOW),
    "lg electronics": (DeviceCategory.TV, RiskLevel.LOW),
    "roku": (DeviceCategory.TV, RiskLevel.LOW),
    # LOW risk - common devices
    "intel": (DeviceCategory.COMPUTER, RiskLevel.LOW),
    "dell": (DeviceCategory.COMPUTER, RiskLevel.LOW),
    "lenovo": (DeviceCategory.COMPUTER, RiskLevel.LOW),
    "hewlett": (DeviceCategory.COMPUTER, RiskLevel.LOW),
    "microsoft": (DeviceCategory.COMPUTER, RiskLevel.LOW),
    # Routers
    "netgear": (DeviceCategory.ROUTER, RiskLevel.LOW),
    "linksys": (DeviceCategory.ROUTER, RiskLevel.LOW),
    "asus": (DeviceCategory.ROUTER, RiskLevel.LOW),
    "arris": (DeviceCategory.ROUTER, RiskLevel.LOW),
    "cisco": (DeviceCategory.ROUTER, RiskLevel.LOW),
    "motorola": (DeviceCategory.ROUTER, RiskLevel.LOW),
}


def lookup_oui_prefix(mac: str) -> str | None:
    """Check if MAC address matches a known camera manufacturer prefix.
    Returns the brand name or None."""
    prefix = mac.upper()[:8]  # "AA:BB:CC"
    return CAMERA_OUI_PREFIXES.get(prefix)


def categorize_by_vendor(vendor: str) -> tuple[DeviceCategory, RiskLevel] | None:
    """Match vendor name against known categories. Returns (category, risk) or None."""
    vendor_lower = vendor.lower()
    for keyword, (category, risk) in VENDOR_CATEGORY_MAP.items():
        if keyword in vendor_lower:
            return category, risk
    return None
