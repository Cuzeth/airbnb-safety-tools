"""Detail panel widget showing selected device information."""

from rich.text import Text
from textual.containers import VerticalScroll

from scanner.models import Device, RiskLevel, PORT_DATABASE


RISK_STYLES = {
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "bold green",
    RiskLevel.UNKNOWN: "dim",
}


class DetailPanel(VerticalScroll):
    """Scrollable panel showing detailed info about the selected device."""

    DEFAULT_CSS = """
    DetailPanel {
        scrollbar-size: 1 1;
    }
    DetailPanel .detail-content {
        width: 1fr;
        height: auto;
    }
    """

    def on_mount(self) -> None:
        from textual.widgets import Static
        content = Static(
            Text("Select a device to view details", style="dim italic"),
            classes="detail-content",
        )
        self.mount(content)

    def show_device(self, device: Device) -> None:
        """Update the panel to show the given device."""
        from textual.widgets import Static

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
                    lines.append(f"\n    {port_info.description}\n", style="dim")
                else:
                    lines.append(f"  {port}\n", style="bold")

        # Numbered openable ports — user presses 1-9 to open specific ones
        openable = device.get_openable_ports()
        if openable:
            lines.append("\nOpen in Browser:\n", style="bold underline")
            for i, (port, url) in enumerate(openable, 1):
                if i > 9:
                    break
                lines.append(f"  [{i}] ", style="bold cyan")
                lines.append(f"{url}\n", style="cyan underline")
            lines.append("\nPress ", style="dim")
            lines.append("1", style="bold cyan")
            if len(openable) > 1:
                lines.append(f"-{min(len(openable), 9)}", style="bold cyan")
            lines.append(" to open  ", style="dim")
            lines.append("o", style="bold cyan")
            lines.append(" opens first\n", style="dim")

        if device.risk_reasons:
            lines.append("\nRisk Analysis:\n", style="bold underline")
            for reason in device.risk_reasons:
                lines.append(f"  \u2022 {reason}\n", style=risk_style)

        if not device.scan_complete:
            lines.append("\n")
            lines.append("Port scan in progress...", style="dim italic")

        # Replace content widget
        try:
            old = self.query_one(".detail-content")
            old.remove()
        except Exception:
            pass
        self.mount(Static(lines, classes="detail-content"))
        self.scroll_home(animate=False)
