"""Detail panel widget showing selected device information."""

from rich.text import Text
from textual.widgets import Static

from scanner.models import Device, RiskLevel, PORT_DATABASE


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

        # Open ports with detailed descriptions
        if device.open_ports:
            lines.append("\nOpen Ports:\n", style="bold underline")
            for port in device.open_ports:
                port_info = PORT_DATABASE.get(port)
                if port_info:
                    port_risk_style = RISK_STYLES.get(port_info.risk, "dim")
                    lines.append(f"  {port}", style="bold")
                    lines.append(f"/{port_info.protocol}", style=port_risk_style)
                    if port_info.web_openable:
                        url = port_info.url_for.format(ip=device.ip) if port_info.url_for else ""
                        lines.append(f" [open: {url}]", style="bold cyan underline")
                    lines.append(f"\n    {port_info.description}\n", style="dim")
                else:
                    lines.append(f"  {port}\n", style="bold")

        # Openable ports summary
        openable = device.get_openable_ports()
        if openable:
            lines.append("\nBrowser-openable:\n", style="bold underline")
            for port, url in openable:
                lines.append(f"  [o] ", style="bold cyan")
                lines.append(f"{url}\n", style="cyan underline")
            lines.append("\nPress ", style="dim")
            lines.append("o", style="bold cyan")
            lines.append(" to open in browser\n", style="dim")

        if device.risk_reasons:
            lines.append("\nRisk Analysis:\n", style="bold underline")
            for reason in device.risk_reasons:
                lines.append(f"  \u2022 {reason}\n", style=risk_style)

        if not device.scan_complete:
            lines.append("\n")
            lines.append("Port scan in progress...", style="dim italic")

        self.update(lines)
