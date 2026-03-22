"""Network discovery: subnet detection and ARP scanning."""

import os
import re
import socket
import subprocess
from ipaddress import IPv4Network

from scanner.models import Device


def get_local_ip() -> str | None:
    """Get the local IP address by connecting to a public DNS (no data sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def detect_subnet() -> str | None:
    """Detect the local /24 subnet. Returns e.g. '192.168.1.0/24'."""
    ip = get_local_ip()
    if not ip:
        return None
    network = IPv4Network(f"{ip}/24", strict=False)
    return str(network)


def is_root() -> bool:
    return os.geteuid() == 0


def arp_scan(subnet: str) -> list[Device]:
    """ARP scan using scapy. Requires root."""
    try:
        # Import scapy here to avoid slow import at module level
        from scapy.all import ARP, Ether, srp, conf

        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=5, verbose=0)

        devices = []
        for sent, received in answered:
            devices.append(Device(
                ip=received.psrc,
                mac=received.hwsrc.upper(),
            ))
        return devices
    except PermissionError:
        return []
    except Exception:
        return []


def nmap_ping_scan(subnet: str) -> list[Device]:
    """Fallback host discovery using nmap -sn (no root needed)."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", subnet],
            capture_output=True, text=True, timeout=60,
        )
        devices = []
        current_ip = None
        for line in result.stdout.splitlines():
            ip_match = re.search(r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
            mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", line)
            if mac_match and current_ip:
                devices.append(Device(
                    ip=current_ip,
                    mac=mac_match.group(1).upper(),
                ))
                current_ip = None
        return devices
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []


def discover_devices(subnet: str) -> list[Device]:
    """Discover devices on the network. Uses ARP if root, falls back to nmap."""
    if is_root():
        devices = arp_scan(subnet)
        if devices:
            return devices
    return nmap_ping_scan(subnet)
