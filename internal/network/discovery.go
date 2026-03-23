package network

import (
	"github.com/cuz/safestay/internal/model"
)

// DiscoverDevices finds devices on the network using the best available method.
func DiscoverDevices(subnet string) ([]*model.Device, error) {
	devices, err := ARPScan(subnet)
	if err != nil {
		return nil, err
	}

	// Filter to only devices in our target subnet
	devices = filterSubnet(devices, subnet)

	return devices, nil
}

// filterSubnet removes devices not in the target /24.
func filterSubnet(devices []*model.Device, subnet string) []*model.Device {
	// Extract the first 3 octets of the subnet for matching
	// e.g., "192.168.1.0/24" → "192.168.1."
	prefix := ""
	dotCount := 0
	for _, c := range subnet {
		if c == '.' {
			dotCount++
		}
		if dotCount == 3 {
			prefix += "."
			break
		}
		prefix += string(c)
	}
	if prefix == "" {
		return devices
	}

	var filtered []*model.Device
	for _, d := range devices {
		if len(d.IP) >= len(prefix) && d.IP[:len(prefix)] == prefix {
			filtered = append(filtered, d)
		}
	}
	return filtered
}
