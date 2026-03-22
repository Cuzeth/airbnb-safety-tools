"""Port scanning for camera-specific ports using nmap."""

import subprocess
import re

from scanner.models import CAMERA_PORTS


def scan_ports(ip: str, ports: list[int] | None = None) -> list[int]:
    """Scan specific ports on a host. Returns list of open port numbers."""
    if ports is None:
        ports = CAMERA_PORTS

    port_str = ",".join(str(p) for p in ports)

    try:
        result = subprocess.run(
            ["nmap", "-sT", "-T4", "--host-timeout", "15s", "-p", port_str, ip],
            capture_output=True, text=True, timeout=30,
        )
        open_ports = []
        for line in result.stdout.splitlines():
            match = re.match(r"(\d+)/tcp\s+open", line)
            if match:
                open_ports.append(int(match.group(1)))
        return open_ports
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
