"""Device fingerprinting: combine OUI lookup, vendor matching, and port analysis."""

from mac_vendor_lookup import MacLookup

from scanner.models import Device, DeviceCategory, RiskLevel, PORT_DATABASE
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

    # 1. Check hardcoded camera OUI
    brand = lookup_oui_prefix(device.mac)
    if brand:
        risk = RiskLevel.HIGH
        category = DeviceCategory.CAMERA
        reasons.append(
            f"MAC prefix matches known camera manufacturer: {brand} "
            f"(OUI {device.mac.upper()[:8]})"
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
    has_streaming_port = False
    has_web_interface = False

    for port in device.open_ports:
        port_info = PORT_DATABASE.get(port)
        if port_info is None:
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
        elif port_info.risk == RiskLevel.MEDIUM:
            reasons.append(
                f"Port {port}/{port_info.protocol}: {port_info.description}"
            )

        if port_info.web_openable:
            has_web_interface = True

    # 4. Combined signal: camera manufacturer + web interface = admin panel
    if category == DeviceCategory.CAMERA and has_web_interface and not has_streaming_port:
        reasons.append(
            "Web interface detected on a camera device — likely an admin panel "
            "where you can view live feeds or change settings"
        )

    # 5. Combined signal: streaming port + web interface = very likely camera
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
