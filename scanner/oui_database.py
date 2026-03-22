"""Known camera and IoT manufacturer MAC prefix database for device fingerprinting.

OUI (Organizationally Unique Identifier) prefixes sourced from IEEE MA-L registry
via maclookup.app and netify.ai. Last verified: 2026-03-22.

References:
  - https://maclookup.app (IEEE OUI lookup)
  - https://standards.ieee.org/products-services/regauth/
  - https://www.netify.ai/resources/macs/brands/
"""

from scanner.models import DeviceCategory, RiskLevel

# MAC OUI prefixes (first 3 bytes, uppercase, colon-separated) for known camera brands.
# Sourced from IEEE MA-L (MAC Address Block Large) registrations.
# These get HIGH risk automatically.
CAMERA_OUI_PREFIXES: dict[str, str] = {
    # ── Hikvision (Hangzhou Hikvision Digital Technology Co.,Ltd.) ────────
    # 81 registered MA-L prefixes. Source: maclookup.app/vendors/hangzhou-hikvision-digital-technology-co-ltd
    "00:BC:99": "Hikvision",
    "04:03:12": "Hikvision",
    "04:EE:CD": "Hikvision",
    "08:3B:C1": "Hikvision",
    "08:54:11": "Hikvision",
    "08:A1:89": "Hikvision",
    "08:CC:81": "Hikvision",
    "0C:75:D2": "Hikvision",
    "10:12:FB": "Hikvision",
    "18:68:CB": "Hikvision",
    "18:80:25": "Hikvision",
    "24:0F:9B": "Hikvision",
    "24:28:FD": "Hikvision",
    "24:32:AE": "Hikvision",
    "24:48:45": "Hikvision",
    "28:57:BE": "Hikvision",
    "2C:A5:9C": "Hikvision",
    "34:09:62": "Hikvision",
    "3C:1B:F8": "Hikvision",
    "40:AC:BF": "Hikvision",
    "44:19:B6": "Hikvision",
    "44:47:CC": "Hikvision",
    "44:A6:42": "Hikvision",
    "48:78:5B": "Hikvision",
    "4C:1F:86": "Hikvision",
    "4C:62:DF": "Hikvision",
    "4C:BD:8F": "Hikvision",
    "4C:F5:DC": "Hikvision",
    "50:E5:38": "Hikvision",
    "54:8C:81": "Hikvision",
    "54:C4:15": "Hikvision",
    "58:03:FB": "Hikvision",
    "58:50:ED": "Hikvision",
    "5C:34:5B": "Hikvision",
    "64:DB:8B": "Hikvision",
    "68:6D:BC": "Hikvision",
    "74:3F:C2": "Hikvision",
    "80:48:9F": "Hikvision",
    "80:7C:62": "Hikvision",
    "80:BE:AF": "Hikvision",
    "80:F5:AE": "Hikvision",
    "84:94:59": "Hikvision",
    "84:9A:40": "Hikvision",
    "88:DE:39": "Hikvision",
    "8C:22:D2": "Hikvision",
    "8C:E7:48": "Hikvision",
    "94:E1:AC": "Hikvision",
    "98:8B:0A": "Hikvision",
    "98:9D:E5": "Hikvision",
    "98:DF:82": "Hikvision",
    "98:F1:12": "Hikvision",
    "A0:FF:0C": "Hikvision",
    "A4:14:37": "Hikvision",
    "A4:29:02": "Hikvision",
    "A4:4B:D9": "Hikvision",
    "A4:A4:59": "Hikvision",
    "A4:D5:C2": "Hikvision",
    "AC:B9:2F": "Hikvision",
    "AC:CB:51": "Hikvision",
    "B4:A3:82": "Hikvision",
    "BC:5E:33": "Hikvision",
    "BC:9B:5E": "Hikvision",
    "BC:AD:28": "Hikvision",
    "BC:BA:C2": "Hikvision",
    "C0:51:7E": "Hikvision",
    "C0:56:E3": "Hikvision",
    "C0:6D:ED": "Hikvision",
    "C4:2F:90": "Hikvision",
    "C8:A7:02": "Hikvision",
    "D4:E8:53": "Hikvision",
    "DC:07:F8": "Hikvision",
    "DC:D2:6A": "Hikvision",
    "E0:BA:AD": "Hikvision",
    "E0:CA:3C": "Hikvision",
    "E0:DF:13": "Hikvision",
    "E4:D5:8B": "Hikvision",
    "E8:A0:ED": "Hikvision",
    "EC:A9:71": "Hikvision",
    "EC:C8:9C": "Hikvision",
    "F8:4D:FC": "Hikvision",
    "FC:9F:FD": "Hikvision",
    # ── Dahua (Zhejiang Dahua Technology Co., Ltd.) ───────────────────────
    # 27 registered MA-L prefixes. Source: maclookup.app/vendors/zhejiang-dahua-technology-co-ltd
    "08:ED:ED": "Dahua",
    "14:A7:8B": "Dahua",
    "24:52:6A": "Dahua",
    "38:AF:29": "Dahua",
    "3C:E3:6B": "Dahua",
    "3C:EF:8C": "Dahua",
    "4C:11:BF": "Dahua",
    "5C:F5:1A": "Dahua",
    "64:FD:29": "Dahua",
    "6C:1C:71": "Dahua",
    "74:C9:29": "Dahua",
    "8C:E9:B4": "Dahua",
    "90:02:A9": "Dahua",
    "98:F9:CC": "Dahua",
    "9C:14:63": "Dahua",
    "A0:BD:1D": "Dahua",
    "B4:4C:3B": "Dahua",
    "BC:32:5F": "Dahua",
    "C0:39:5A": "Dahua",
    "C4:AA:C4": "Dahua",
    "D4:43:0E": "Dahua",
    "E0:2E:FE": "Dahua",
    "E0:50:8B": "Dahua",
    "E4:24:6C": "Dahua",
    "F4:B1:C2": "Dahua",
    "FC:5F:49": "Dahua",
    "FC:B6:9D": "Dahua",
    # ── Wyze (Wyze Labs Inc) ─────────────────────────────────────────────
    # 6 registered prefixes. Source: maclookup.app/vendors/wyze-labs-inc
    "2C:AA:8E": "Wyze",
    "7C:78:B2": "Wyze",
    "80:48:2C": "Wyze",
    "A4:DA:22": "Wyze",  # MA-M block
    "D0:3F:27": "Wyze",
    "F0:C8:8B": "Wyze",
    # ── Ring (Ring LLC) ──────────────────────────────────────────────────
    # 12 registered MA-L prefixes. Source: maclookup.app/vendors/ring-llc
    "00:B4:63": "Ring",
    "18:7F:88": "Ring",
    "24:2B:D6": "Ring",
    "34:3E:A4": "Ring",
    "54:E0:19": "Ring",
    "5C:47:5E": "Ring",
    "64:9A:63": "Ring",
    "90:48:6C": "Ring",
    "9C:76:13": "Ring",
    "AC:9F:C3": "Ring",
    "C4:DB:AD": "Ring",
    "CC:3B:FB": "Ring",
    # ── Axis Communications ──────────────────────────────────────────────
    # Major IP camera manufacturer (Swedish). OUI verified via IEEE.
    "00:40:8C": "Axis",
    "AC:CC:8E": "Axis",
    "B8:A4:4F": "Axis",
    # ── Foscam (Shenzhen Foscam Intelligent Technology Co., Ltd.) ────────
    "C0:61:18": "Foscam",
    "00:0D:C5": "Foscam",  # Older Foscam OUI
    # ── Amcrest Technologies ─────────────────────────────────────────────
    # 4 registered prefixes. Source: maclookup.app/vendors/amcrest-technologies
    "9C:8E:CD": "Amcrest",
    "A0:60:32": "Amcrest",
    "00:65:1E": "Amcrest",
    "34:46:63": "Amcrest",  # MA-M block
    # ── Reolink (Reolink Innovation Limited) ─────────────────────────────
    # 1 registered MA-L prefix. Source: maclookup.app/vendors/reolink-innovation-limited
    "EC:71:DB": "Reolink",
    "B4:6D:83": "Reolink",  # Some devices use this via OEM chipset
    # ── Arlo (Arlo Technologies) ─────────────────────────────────────────
    # 3 registered MA-L prefixes. Source: netify.ai/resources/macs/brands/arlo
    "48:62:64": "Arlo",
    "A4:11:62": "Arlo",
    "FC:9C:98": "Arlo",
    "20:3D:BD": "Arlo",  # Older/Netgear era
    "6C:4A:85": "Arlo",
    "9C:E6:35": "Arlo",
    # ── Vivotek ──────────────────────────────────────────────────────────
    "00:02:D1": "Vivotek",
    # ── Uniview (Zhejiang Uniview Technologies) ──────────────────────────
    "24:24:05": "Uniview",
    # ── TP-Link / Tapo cameras ───────────────────────────────────────────
    # Note: TP-Link makes many products; these prefixes appear on Tapo cameras.
    # Vendor lookup will show "TP-Link" — fingerprinting relies on port scan to confirm camera.
    "60:32:B1": "TP-Link/Tapo",
    "98:25:4A": "TP-Link/Tapo",
    # ── Eufy / Anker Innovations ─────────────────────────────────────────
    # Eufy cameras sold under Anker brand. 78:8C:B5 is actually TP-Link (corrected).
    # Eufy uses Anker Innovations OUIs — matched via vendor string instead.
    # ── Nest (Google) ────────────────────────────────────────────────────
    # Nest cameras now under Google branding. These are legacy Nest Inc OUIs.
    "18:B4:30": "Nest",
    "64:16:66": "Nest",
    # ── Hanwha Techwin (formerly Samsung Techwin) ────────────────────────
    # Major surveillance manufacturer (Wisenet cameras).
    "00:09:18": "Hanwha/Wisenet",
    "00:16:63": "Hanwha/Wisenet",
    # ── FLIR Systems ─────────────────────────────────────────────────────
    "00:40:7F": "FLIR",
    # ── Lorex (subsidiary of Dahua) ──────────────────────────────────────
    # Lorex cameras often use Dahua OUIs since they're Dahua rebadges.
    # Matched primarily through vendor string lookup.
    # ── Swann ────────────────────────────────────────────────────────────
    # Consumer camera brand, often uses OEM chipsets (Xiongmai/HiSilicon).
    # Matched primarily through vendor string lookup.
    # ── Xiongmai / XMEye (common cheap IP camera chipset) ────────────────
    # Very common in budget/unbranded cameras. Uses custom protocol on port 34567.
    "00:12:12": "Xiongmai/XMEye",
    "00:12:13": "Xiongmai/XMEye",
    "00:12:14": "Xiongmai/XMEye",
    "00:12:15": "Xiongmai/XMEye",
    "00:12:16": "Xiongmai/XMEye",
    "00:12:17": "Xiongmai/XMEye",
    # ── Ubiquiti (UniFi Protect cameras) ─────────────────────────────────
    "24:5A:4C": "Ubiquiti/UniFi",
    "68:D7:9A": "Ubiquiti/UniFi",
    "74:83:C2": "Ubiquiti/UniFi",
    "78:8A:20": "Ubiquiti/UniFi",
    "80:2A:A8": "Ubiquiti/UniFi",
    "B4:FB:E4": "Ubiquiti/UniFi",
    "F0:9F:C2": "Ubiquiti/UniFi",
    "FC:EC:DA": "Ubiquiti/UniFi",
    # ── Xiongmai additional (appropriated from defunct companies) ────────
    "00:12:10": "Xiongmai/XMEye",
    "00:12:11": "Xiongmai/XMEye",
}

# ══════════════════════════════════════════════════════════════════════
# CHIPSET VENDORS — WiFi modules commonly found inside hidden cameras.
# These are NOT camera brands; they are the WiFi chips soldered onto
# cheap camera PCBs (Anyka AK3918, Ingenic T20, Goke GK7102, etc.).
# Kept separate from CAMERA_OUI_PREFIXES because these chips also
# appear in non-camera devices (printers, TVs, IoT). The port scan
# determines if it's actually a camera.
# ══════════════════════════════════════════════════════════════════════
CHIPSET_OUI_PREFIXES: dict[str, str] = {
    # ── Realtek Semiconductor (RTL8188/RTL8189/RTL8192 WiFi modules) ─────
    # THE most common WiFi chip in hidden spy cameras. Also in printers,
    # smart TVs, etc., so MEDIUM risk until ports confirm.
    "00:E0:4C": "Realtek [WiFi module]",
    "52:54:00": "Realtek [WiFi module]",
    # ── MediaTek / Ralink (MT7601/MT7628 WiFi modules) ───────────────────
    # MT7601U is extremely common in Goke GK7102-based spy cameras.
    # 00:0C:43 was originally Ralink Technology, acquired by MediaTek 2011.
    "00:0C:43": "MediaTek/Ralink [WiFi module]",
    "00:0C:E7": "MediaTek [WiFi module]",
    "00:0A:00": "MediaTek [WiFi module]",
    "00:17:A5": "MediaTek [WiFi module]",
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
    "wisenet": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "flir": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "lorex": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "swann": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "xiongmai": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "xmeye": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "tapo": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "jovision": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    # MEDIUM risk - chipset vendors found inside hidden cameras
    # These WiFi chips are in many devices, but combined with camera ports → HIGH
    "realtek": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "ralink": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "mediatek": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "anyka": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "goke": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "ingenic": (DeviceCategory.CAMERA, RiskLevel.HIGH),
    "hisilicon": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    # MEDIUM risk - IoT / smart home
    "amazon": (DeviceCategory.SMART_SPEAKER, RiskLevel.MEDIUM),
    "google": (DeviceCategory.SMART_HOME, RiskLevel.MEDIUM),
    "apple": (DeviceCategory.PHONE, RiskLevel.LOW),
    "sonos": (DeviceCategory.SMART_SPEAKER, RiskLevel.MEDIUM),
    "tuya": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "shelly": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "espressif": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
    "tp-link": (DeviceCategory.IOT_GENERIC, RiskLevel.MEDIUM),
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
    Returns the brand name or None. Does NOT match chipset-only vendors."""
    prefix = mac.upper()[:8]  # "AA:BB:CC"
    return CAMERA_OUI_PREFIXES.get(prefix)


def lookup_chipset_prefix(mac: str) -> str | None:
    """Check if MAC address matches a known WiFi chipset vendor.
    Returns chipset name or None. These are MEDIUM risk (not HIGH)."""
    prefix = mac.upper()[:8]
    return CHIPSET_OUI_PREFIXES.get(prefix)


def lookup_any_prefix(mac: str) -> str | None:
    """Check camera brands first, then chipset vendors. Returns name or None."""
    return lookup_oui_prefix(mac) or lookup_chipset_prefix(mac)


def categorize_by_vendor(vendor: str) -> tuple[DeviceCategory, RiskLevel] | None:
    """Match vendor name against known categories. Returns (category, risk) or None."""
    vendor_lower = vendor.lower()
    for keyword, (category, risk) in VENDOR_CATEGORY_MAP.items():
        if keyword in vendor_lower:
            return category, risk
    return None
