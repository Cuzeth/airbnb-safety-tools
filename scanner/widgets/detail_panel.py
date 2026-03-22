"""Detail panel widget showing selected device information."""

from rich.text import Text
from textual.widgets import Static

from scanner.models import Device, RiskLevel


RISK_STYLES = {
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "bold green",
    RiskLevel.UNKNOWN: "dim",
}


class DetailPanel(Static):
    """Panel showing detailed info about the selected device."""

    def on_mount(self) -> None:
        self.update(Text("Select a device to view details", style="dim italic"))

    def show_device(self, device: Device) -> None:
        """Update the panel to show the given device."""
        lines = Text()

        lines.append("DEVICE DETAILS\n", style="bold underline")
        lines.append("\n")

        lines.append("IP:       ", style="bold")
        lines.append(f"{device.ip}\n")

        lines.append("MAC:      ", style="bold")
        lines.append(f"{device.mac}\n")

        lines.append("Vendor:   ", style="bold")
        lines.append(f"{device.vendor}\n")

        lines.append("Category: ", style="bold")
        lines.append(f"{device.category.value}\n")

        lines.append("\nRisk:     ", style="bold")
        risk_style = RISK_STYLES.get(device.risk_level, "dim")
        lines.append(f"{device.risk_level.value.upper()}\n", style=risk_style)

        if device.open_ports:
            lines.append("\nOpen Ports:\n", style="bold")
            for port in device.open_ports:
                lines.append(f"  {port}\n")

        if device.risk_reasons:
            lines.append("\nRisk Reasons:\n", style="bold")
            for reason in device.risk_reasons:
                lines.append(f"  - {reason}\n", style=risk_style)

        if not device.scan_complete:
            lines.append("\n")
            lines.append("Port scan in progress...", style="dim italic")

        self.update(lines)
