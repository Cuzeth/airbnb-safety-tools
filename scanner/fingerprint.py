"""Device fingerprinting: combine OUI lookup, vendor matching, and port analysis."""

from mac_vendor_lookup import MacLookup

from scanner.models import Device, DeviceCategory, RiskLevel, PORT_DATABASE
from scanner.oui_database import categorize_by_vendor, lookup_any_prefix, lookup_chipset_prefix, lookup_oui_prefix

_mac_lookup: MacLookup | None = None


def _get_mac_lookup() -> MacLookup:
    global _mac_lookup
    if _mac_lookup is None:
        _mac_lookup = MacLookup()
    return _mac_lookup


def lookup_vendor(device: Device) -> None:
    """Look up the vendor name from MAC address and set it on the device."""
    # First check our hardcoded camera OUI database
    brand = lookup_oui_prefix(device.mac)
    if brand:
        device.vendor = brand
        return

    # Check chipset vendor OUI (Realtek, MediaTek, etc.)
    chipset = lookup_chipset_prefix(device.mac)
    if chipset:
        device.vendor = chipset
        return

    # Fall back to mac-vendor-lookup library
    try:
        vendor = _get_mac_lookup().lookup(device.mac)
        if vendor:
            device.vendor = vendor
    except Exception:
        device.vendor = "Unknown"


def fingerprint_device(device: Device) -> None:
    """Analyze device and assign risk level, category, and reasons.

    Risk assessment combines three signals:
    1. MAC OUI prefix — known camera manufacturers get HIGH immediately
    2. Vendor name matching — fallback for OUIs not in our database
    3. Open port analysis — camera-specific protocols are strong indicators
    """
    reasons: list[str] = []
    risk = RiskLevel.LOW
    category = DeviceCategory.UNKNOWN

    # 1. Check hardcoded camera OUI (brand-name cameras → HIGH)
    brand = lookup_oui_prefix(device.mac)
    chipset = lookup_chipset_prefix(device.mac)
    if brand:
        risk = RiskLevel.HIGH
        category = DeviceCategory.CAMERA
        reasons.append(
            f"MAC prefix matches known camera manufacturer: {brand} "
            f"(OUI {device.mac.upper()[:8]})"
        )
    elif chipset:
        # Chipset vendor (Realtek, MediaTek) — MEDIUM until ports confirm
        risk = RiskLevel.MEDIUM
        category = DeviceCategory.IOT_GENERIC
        reasons.append(
            f"WiFi chipset vendor: {chipset} (OUI {device.mac.upper()[:8]}) — "
            "commonly found inside hidden cameras, but also in many other IoT devices"
        )

    # 2. Check vendor name keywords
    if device.vendor and device.vendor != "Unknown":
        result = categorize_by_vendor(device.vendor)
        if result:
            cat, vendor_risk = result
            if _risk_priority(vendor_risk) > _risk_priority(risk):
                risk = vendor_risk
            if category == DeviceCategory.UNKNOWN:
                category = cat
            if vendor_risk in (RiskLevel.HIGH, RiskLevel.MEDIUM):
                reasons.append(
                    f"Vendor \"{device.vendor}\" is a known {cat.value} manufacturer"
                )

    # 3. Check open ports against our detailed port database
    #    But first: known consumer brands (Apple, Samsung, etc.) use ports like
    #    5000 (AirPlay), 80 (settings), 3478 (FaceTime STUN) for normal services.
    #    Don't flag those as suspicious.
    is_safe_vendor = _is_known_safe_vendor(device.vendor)
    has_streaming_port = False
    has_web_interface = False
    has_p2p_port = False
    has_backdoor = False

    for port in device.open_ports:
        port_info = PORT_DATABASE.get(port)
        if port_info is None:
            continue

        # Skip false-positive ports on known safe vendors
        if is_safe_vendor and port in _SAFE_VENDOR_IGNORE_PORTS:
            reasons.append(
                f"Port {port}/{port_info.protocol}: "
                f"{_SAFE_VENDOR_IGNORE_PORTS[port]} (normal for {device.vendor})"
            )
            continue

        if _risk_priority(port_info.risk) > _risk_priority(risk):
            risk = port_info.risk

        if port_info.risk == RiskLevel.HIGH:
            reasons.append(
                f"Port {port}/{port_info.protocol}: {port_info.description}"
            )
            if category == DeviceCategory.UNKNOWN:
                category = DeviceCategory.CAMERA
            has_streaming_port = True
            # Track specific hidden-camera indicators
            if port in (32100, 8600):
                has_p2p_port = True
            if port in (23, 9527):
                has_backdoor = True
        elif port_info.risk == RiskLevel.MEDIUM:
            reasons.append(
                f"Port {port}/{port_info.protocol}: {port_info.description}"
            )

        if port_info.web_openable:
            has_web_interface = True

    # 4. Chipset vendor + camera ports = likely hidden camera
    # Generic WiFi chip vendors (Realtek, MediaTek, Espressif) are MEDIUM on their
    # own, but if they also have camera-specific ports open, escalate to HIGH.
    is_chipset_vendor = _is_generic_chipset_vendor(device.vendor)
    if is_chipset_vendor and has_streaming_port:
        risk = RiskLevel.HIGH
        category = DeviceCategory.CAMERA
        reasons.append(
            f"Generic WiFi chipset ({device.vendor}) with camera ports open — "
            "likely a hidden/spy camera using a commodity WiFi module "
            "(Anyka, Ingenic, or Goke SoC)"
        )

    # 5. P2P port is an extremely strong hidden camera indicator
    if has_p2p_port:
        risk = RiskLevel.HIGH
        category = DeviceCategory.CAMERA
        reasons.append(
            "P2P cloud protocol detected — this is the primary communication "
            "method for hidden spy cameras. The device streams video to a cloud "
            "relay server rather than exposing local RTSP"
        )

    # 6. Telnet/debug backdoor on IoT device = cheap camera
    if has_backdoor and category in (DeviceCategory.IOT_GENERIC, DeviceCategory.UNKNOWN):
        if any(p in device.open_ports for p in (554, 8554, 10554, 80, 81, 32100)):
            risk = RiskLevel.HIGH
            category = DeviceCategory.CAMERA
            reasons.append(
                "Debug backdoor + media ports on unknown device — strong indicator "
                "of a cheap Chinese IP camera with default firmware"
            )

    # 7. Combined signal: camera manufacturer + web interface = admin panel
    if category == DeviceCategory.CAMERA and has_web_interface and not has_streaming_port:
        reasons.append(
            "Web interface detected on a camera device — likely an admin panel "
            "where you can view live feeds or change settings"
        )

    # 8. Combined signal: streaming port + web interface = very likely camera
    if has_streaming_port and has_web_interface:
        reasons.append(
            "Both streaming protocol and web interface detected — "
            "strong indicator of an active IP camera"
        )

    device.risk_level = risk
    device.category = category
    device.risk_reasons = reasons
    device.scan_complete = True


def _risk_priority(risk: RiskLevel) -> int:
    return {
        RiskLevel.UNKNOWN: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
    }[risk]


# Vendor strings that indicate a generic WiFi chipset (not a camera brand).
# When these appear WITH camera-specific ports, it strongly suggests a hidden camera.
_CHIPSET_VENDORS = (
    "realtek", "ralink", "mediatek", "espressif", "hisilicon",
    "wifi module", "wireless", "semiconductor",
)


def _is_generic_chipset_vendor(vendor: str) -> bool:
    """Check if vendor string looks like a WiFi chip manufacturer rather than a device brand."""
    if not vendor or vendor == "Unknown":
        return False
    v = vendor.lower()
    return any(chip in v for chip in _CHIPSET_VENDORS)


# Vendors where certain ports are expected and should NOT raise risk.
# e.g. Apple uses 5000 (AirPlay), 3478 (FaceTime STUN), 80 (config).
_SAFE_VENDORS = (
    "apple", "samsung", "google", "sonos", "roku",
    "lg electronics", "microsoft", "intel", "dell", "lenovo",
    "hewlett", "netgear", "linksys", "asus", "arris", "cisco", "motorola",
)

# Ports to ignore on safe vendors, with explanation.
_SAFE_VENDOR_IGNORE_PORTS: dict[int, str] = {
    5000: "AirPlay / smart device service",
    5001: "AirPlay SSL / smart device service",
    80: "Device settings web UI",
    443: "Device settings HTTPS",
    3478: "FaceTime / VoIP STUN",
    8080: "Device management",
    9000: "Device service port",
}


def _is_known_safe_vendor(vendor: str) -> bool:
    """Check if the vendor is a known consumer electronics brand (not a camera company)."""
    if not vendor or vendor == "Unknown":
        return False
    v = vendor.lower()
    return any(safe in v for safe in _SAFE_VENDORS)
