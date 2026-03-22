"""Device fingerprinting: combine OUI lookup, vendor matching, and port analysis."""

from mac_vendor_lookup import MacLookup

from scanner.models import Device, DeviceCategory, RiskLevel
from scanner.oui_database import categorize_by_vendor, lookup_oui_prefix

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

    # Fall back to mac-vendor-lookup library
    try:
        vendor = _get_mac_lookup().lookup(device.mac)
        if vendor:
            device.vendor = vendor
    except Exception:
        device.vendor = "Unknown"


# Ports that strongly suggest a camera/streaming device
HIGH_RISK_PORTS = {
    554: "RTSP streaming port (common on cameras)",
    8554: "Alternate RTSP port",
    37777: "Dahua camera protocol port",
    37778: "Dahua camera protocol port",
    8000: "Hikvision camera protocol port",
    8200: "Hikvision camera protocol port",
    6668: "Wyze camera port",
    6669: "Wyze camera port",
    1935: "RTMP streaming port",
}

# Ports that are somewhat suspicious on unknown devices
MEDIUM_RISK_PORTS = {
    8080: "Alternate HTTP (possible camera web interface)",
    8443: "Alternate HTTPS (possible camera web interface)",
    9000: "Possible camera management port",
    5000: "Possible NAS/surveillance station",
    5001: "Possible NAS/surveillance station (SSL)",
    3478: "STUN/TURN (WebRTC, used by some cameras)",
}


def fingerprint_device(device: Device) -> None:
    """Analyze device and assign risk level, category, and reasons."""
    reasons: list[str] = []
    risk = RiskLevel.LOW
    category = DeviceCategory.UNKNOWN

    # 1. Check hardcoded camera OUI
    brand = lookup_oui_prefix(device.mac)
    if brand:
        risk = RiskLevel.HIGH
        category = DeviceCategory.CAMERA
        reasons.append(f"Known camera manufacturer: {brand}")

    # 2. Check vendor name keywords
    if device.vendor and device.vendor != "Unknown":
        result = categorize_by_vendor(device.vendor)
        if result:
            cat, vendor_risk = result
            if vendor_risk.value > risk.value or risk == RiskLevel.LOW:
                # Enum comparison: HIGH > MEDIUM > LOW
                if _risk_priority(vendor_risk) > _risk_priority(risk):
                    risk = vendor_risk
            if category == DeviceCategory.UNKNOWN:
                category = cat
            if vendor_risk in (RiskLevel.HIGH, RiskLevel.MEDIUM):
                reasons.append(f"Vendor '{device.vendor}' associated with {cat.value}")

    # 3. Check open ports
    for port in device.open_ports:
        if port in HIGH_RISK_PORTS:
            risk = RiskLevel.HIGH
            reasons.append(f"Port {port}: {HIGH_RISK_PORTS[port]}")
            if category == DeviceCategory.UNKNOWN:
                category = DeviceCategory.CAMERA
        elif port in MEDIUM_RISK_PORTS:
            if _risk_priority(RiskLevel.MEDIUM) > _risk_priority(risk):
                risk = RiskLevel.MEDIUM
            reasons.append(f"Port {port}: {MEDIUM_RISK_PORTS[port]}")

    # 4. HTTP ports on camera-category devices bump confidence
    if category == DeviceCategory.CAMERA and any(p in device.open_ports for p in (80, 443)):
        reasons.append("HTTP/HTTPS web interface (likely camera admin panel)")

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
