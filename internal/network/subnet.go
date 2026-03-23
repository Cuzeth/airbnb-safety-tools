package network

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

// GetLocalIP returns the local IP address by connecting to a public DNS (no data sent).
func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
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

	// Apply /24 mask
	mask := net.CIDRMask(24, 32)
	network := parsed.Mask(mask)
	return fmt.Sprintf("%s/24", network.String()), nil
}

// IsRoot checks if the process is running with elevated privileges.
func IsRoot() bool {
	if runtime.GOOS == "windows" {
		// On Windows, check for admin by attempting to open a privileged path
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	return os.Geteuid() == 0
}
