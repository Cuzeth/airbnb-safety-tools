package network

import (
	"net"
	"strings"

	"abdeen.dev/safestay/internal/model"
)

// DiscoveryResult bundles the discovered devices with metadata about how
// reliable that result is. AP/client isolation networks can return 0-2 devices
// even when many real devices (including hidden cameras) are present, so the
// caller must surface this to the user — a clean result on an isolated network
// is not the same as a clean result on a normal network.
type DiscoveryResult struct {
	Devices     []*model.Device
	Reliability model.ScanReliability
	GatewayIP   string
	LocalIP     string
}

// DiscoverDevices finds devices on the subnet and returns a result describing
// how trustworthy that coverage is.
func DiscoverDevices(subnet string) (DiscoveryResult, error) {
	devices, err := ARPScan(subnet)
	if err != nil {
		return DiscoveryResult{}, err
	}

	devices = filterSubnet(devices, subnet)

	gateway := guessGateway(subnet)
	local, _ := GetLocalIP()

	return DiscoveryResult{
		Devices:     devices,
		Reliability: assessReliability(devices, gateway, local),
		GatewayIP:   gateway,
		LocalIP:     local,
	}, nil
}

// assessReliability classifies the scan based on how many devices we saw and
// whether they look like just "the user's own machine + the router".
func assessReliability(devices []*model.Device, gateway, local string) model.ScanReliability {
	if len(devices) == 0 {
		return model.ReliabilityIsolated
	}

	nonInfra := 0
	for _, d := range devices {
		if d.IP == gateway || d.IP == local {
			continue
		}
		nonInfra++
	}

	if nonInfra == 0 {
		return model.ReliabilityIsolated
	}
	if len(devices) <= 2 {
		return model.ReliabilityPartial
	}
	return model.ReliabilityNormal
}

// guessGateway returns the most likely default-gateway IP for a /24, e.g. .1.
// This is a heuristic; we use it only to recognise the router in scan output,
// not to route traffic.
func guessGateway(subnet string) string {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return ""
	}
	gw := make(net.IP, 4)
	copy(gw, ip)
	gw[3] = 1
	return gw.String()
}

// filterSubnet removes devices not in the target /24.
func filterSubnet(devices []*model.Device, subnet string) []*model.Device {
	prefix := subnetPrefix(subnet)
	if prefix == "" {
		return devices
	}

	var filtered []*model.Device
	for _, d := range devices {
		if strings.HasPrefix(d.IP, prefix) {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

func subnetPrefix(subnet string) string {
	dotCount := 0
	for i, c := range subnet {
		if c == '.' {
			dotCount++
			if dotCount == 3 {
				return subnet[:i+1]
			}
		}
	}
	return ""
}
