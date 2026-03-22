"""Device table widget for displaying discovered devices."""

from rich.text import Text
from textual.widgets import DataTable

from scanner.models import Device, RiskLevel


RISK_ICONS = {
    RiskLevel.HIGH: Text("  HIGH  ", style="bold white on red"),
    RiskLevel.MEDIUM: Text(" MEDIUM ", style="bold black on yellow"),
    RiskLevel.LOW: Text("  LOW   ", style="bold white on green"),
    RiskLevel.UNKNOWN: Text("   ?    ", style="dim"),
}


class DeviceTable(DataTable):
    """Table displaying network devices with risk indicators."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.add_columns("Risk", "IP Address", "MAC Address", "Vendor", "Category", "Ports")

    def add_device(self, device: Device) -> None:
        """Add a device row to the table."""
        risk_icon = RISK_ICONS.get(device.risk_level, RISK_ICONS[RiskLevel.UNKNOWN])
        ports_str = ", ".join(str(p) for p in device.open_ports) if device.open_ports else "-"
        self.add_row(
            risk_icon,
            device.ip,
            device.mac,
            _truncate(device.vendor, 20),
            device.category.value,
            ports_str if device.scan_complete else "scanning...",
            key=device.mac,
        )

    def update_device(self, device: Device) -> None:
        """Update an existing device row after port scan completes."""
        try:
            self.remove_row(device.mac)
        except Exception:
            pass
        self.add_device(device)


def _truncate(text: str, length: int) -> str:
    if len(text) <= length:
        return text
    return text[: length - 1] + "\u2026"
