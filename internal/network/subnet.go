package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
)

// GetLocalIP returns the local non-loopback IPv4 address by enumerating
// network interfaces. It does not contact any external host. If multiple
// candidate interfaces are present, the first non-loopback IPv4 with a
// /24-or-narrower mask is preferred (typical for WiFi/LAN), falling back to
// the first non-loopback IPv4 of any prefix.
func GetLocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var fallback string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			if ones >= 24 {
				return v4.String(), nil
			}
			if fallback == "" {
				fallback = v4.String()
			}
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", errors.New("no non-loopback IPv4 address found")
}

// DetectSubnet returns the local /24 subnet (e.g. "192.168.1.0/24").
func DetectSubnet() (string, error) {
	ip, err := GetLocalIP()
	if err != nil {
		return "", err
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP: %s", ip)
	}

	mask := net.CIDRMask(24, 32)
	network := parsed.Mask(mask)
	return fmt.Sprintf("%s/24", network.String()), nil
}

// IsRoot checks if the process is running with elevated privileges.
func IsRoot() bool {
	if runtime.GOOS == "windows" {
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	return os.Geteuid() == 0
}
