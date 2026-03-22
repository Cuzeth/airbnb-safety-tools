"""SafeStay Scanner - Main TUI application."""

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Static

from scanner.fingerprint import fingerprint_device, lookup_vendor
from scanner.models import Device, RiskLevel
from scanner.network import detect_subnet, discover_devices, is_root
from scanner.ports import scan_ports
from scanner.widgets.detail_panel import DetailPanel
from scanner.widgets.device_table import DeviceTable


class SafeStayApp(App):
    """Network scanner TUI for detecting hidden cameras."""

    TITLE = "SafeStay Scanner"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("s", "start_scan", "Scan Network"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.devices: dict[str, Device] = {}
        self.subnet: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self._banner(), id="banner")
        with Horizontal(id="main"):
            yield DeviceTable(id="device-table")
            yield DetailPanel(id="detail-panel")
        yield Static("Press [bold]s[/bold] to scan  |  Devices: 0", id="status-bar")
        yield Footer()

    def _banner(self) -> str:
        parts = []
        if not is_root():
            parts.append(
                "[bold yellow]Warning:[/] Not running as root. "
                "ARP scanning disabled (using nmap fallback). "
                "Run with [bold]sudo[/] for best results."
            )
        subnet = detect_subnet()
        self.subnet = subnet
        if subnet:
            parts.append(f"Network: [bold cyan]{subnet}[/]")
        else:
            parts.append("[bold red]Could not detect network.[/] Are you connected to WiFi?")
        return "  |  ".join(parts)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update detail panel when a row is selected."""
        if event.row_key and event.row_key.value in self.devices:
            panel = self.query_one("#detail-panel", DetailPanel)
            panel.show_device(self.devices[event.row_key.value])

    def action_start_scan(self) -> None:
        """Start network scan."""
        if not self.subnet:
            self.notify("No network detected!", severity="error")
            return
        self.notify(f"Scanning {self.subnet}...")
        self._run_scan()

    @work(exclusive=True, thread=True)
    def _run_scan(self) -> None:
        """Background worker: discover devices and scan ports."""
        table: DeviceTable = self.query_one("#device-table", DeviceTable)  # type: ignore[assignment]
        status: Static = self.query_one("#status-bar", Static)  # type: ignore[assignment]

        # Clear previous results
        self.call_from_thread(table.clear)
        self.devices.clear()

        # Discover devices
        self.call_from_thread(status.update, "Discovering devices...")
        devices = discover_devices(self.subnet)  # type: ignore[arg-type]

        if not devices:
            self.call_from_thread(
                status.update,
                "[bold red]No devices found.[/] The network may use AP isolation.",
            )
            self.call_from_thread(
                self.notify,
                "No devices found. Network may use client isolation.",
                severity="warning",
            )
            return

        # Phase 1: Show all devices with vendor lookup (fast)
        for device in devices:
            lookup_vendor(device)
            self.devices[device.mac] = device
            self.call_from_thread(table.add_device, device)

        count = len(devices)
        self.call_from_thread(
            status.update,
            f"Found {count} devices. Port scanning in progress...",
        )

        # Phase 2: Port scan each device (slow)
        for i, device in enumerate(devices, 1):
            self.call_from_thread(
                status.update,
                f"Port scanning {i}/{count}: {device.ip}...",
            )
            device.open_ports = scan_ports(device.ip)
            fingerprint_device(device)
            self.call_from_thread(table.update_device, device)

        # Summary
        high = sum(1 for d in devices if d.risk_level == RiskLevel.HIGH)
        medium = sum(1 for d in devices if d.risk_level == RiskLevel.MEDIUM)
        low = count - high - medium

        summary = (
            f"Scan complete  |  "
            f"Devices: {count}  |  "
            f"[bold red]HIGH: {high}[/]  |  "
            f"[bold yellow]MEDIUM: {medium}[/]  |  "
            f"[green]LOW: {low}[/]"
        )
        self.call_from_thread(status.update, summary)

        if high > 0:
            self.call_from_thread(
                self.notify,
                f"Found {high} HIGH risk device(s)!",
                severity="error",
                timeout=10,
            )
