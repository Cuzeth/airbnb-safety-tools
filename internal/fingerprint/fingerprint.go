package fingerprint

import (
	"fmt"
	"strings"

	"github.com/cuz/safestay/internal/model"
	"github.com/cuz/safestay/internal/oui"
)

// chipsetVendors are vendor strings indicating a generic WiFi chipset (not a camera brand).
var chipsetVendors = []string{
	"realtek", "ralink", "mediatek", "espressif", "hisilicon",
	"wifi module", "wireless", "semiconductor",
}

// safeVendors are known consumer electronics brands (not camera companies).
var safeVendors = []string{
	"apple", "samsung", "google", "sonos", "roku",
	"lg electronics", "microsoft", "intel", "dell", "lenovo",
	"hewlett", "netgear", "linksys", "asus", "arris", "cisco", "motorola",
}

// safeVendorIgnorePorts maps ports to explanations for known safe vendors.
var safeVendorIgnorePorts = map[int]string{
	5000: "AirPlay / smart device service",
	5001: "AirPlay SSL / smart device service",
	80:   "Device settings web UI",
	443:  "Device settings HTTPS",
	3478: "FaceTime / VoIP STUN",
	8080: "Device management",
	9000: "Device service port",
}

// LookupVendor sets the vendor name on a device using 3-tier lookup.
func LookupVendor(device *model.Device) {
	// 1. Check hardcoded camera OUI database
	if brand := oui.LookupOUIPrefix(device.MAC); brand != "" {
		device.Vendor = brand
		return
	}

	// 2. Check chipset vendor OUI
	if chipset := oui.LookupChipsetPrefix(device.MAC); chipset != "" {
		device.Vendor = chipset
		return
	}

	// 3. Fall back to embedded MAC vendor database
	if vendor := oui.LookupFallback(device.MAC); vendor != "" {
		device.Vendor = vendor
		return
	}

	device.Vendor = "Unknown"
}

// FingerprintDevice analyzes a device and assigns risk level, category, and reasons.
// This is a 1:1 port of the Python 8-layer algorithm.
func FingerprintDevice(device *model.Device) {
	var reasons []string
	risk := model.RiskLow
	category := model.CategoryUnknown

	// 1. Check hardcoded camera OUI (brand-name cameras → HIGH)
	brand := oui.LookupOUIPrefix(device.MAC)
	chipset := oui.LookupChipsetPrefix(device.MAC)

	if brand != "" {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons, fmt.Sprintf(
			"MAC prefix matches known camera manufacturer: %s (OUI %s)",
			brand, strings.ToUpper(device.MAC[:8]),
		))
	} else if chipset != "" {
		risk = model.RiskMedium
		category = model.CategoryIOT
		reasons = append(reasons, fmt.Sprintf(
			"WiFi chipset vendor: %s (OUI %s) — "+
				"commonly found inside hidden cameras, but also in many other IoT devices",
			chipset, strings.ToUpper(device.MAC[:8]),
		))
	}

	// 2. Check vendor name keywords
	if device.Vendor != "" && device.Vendor != "Unknown" {
		cat, vendorRisk, found := oui.CategorizeByVendor(device.Vendor)
		if found {
			if riskPriority(vendorRisk) > riskPriority(risk) {
				risk = vendorRisk
			}
			if category == model.CategoryUnknown {
				category = cat
			}
			if vendorRisk == model.RiskHigh || vendorRisk == model.RiskMedium {
				reasons = append(reasons, fmt.Sprintf(
					"Vendor \"%s\" is a known %s manufacturer",
					device.Vendor, string(cat),
				))
			}
		}
	}

	// 3. Check open ports against port database
	isSafeVendor := isKnownSafeVendor(device.Vendor)
	hasStreamingPort := false
	hasWebInterface := false
	hasP2PPort := false
	hasBackdoor := false

	for _, port := range device.OpenPorts {
		portInfo, ok := model.PortDatabase[port]
		if !ok {
			continue
		}

		// Skip false-positive ports on known safe vendors
		if isSafeVendor {
			if explanation, ignored := safeVendorIgnorePorts[port]; ignored {
				reasons = append(reasons, fmt.Sprintf(
					"Port %d/%s: %s (normal for %s)",
					port, portInfo.Protocol, explanation, device.Vendor,
				))
				continue
			}
		}

		if riskPriority(portInfo.Risk) > riskPriority(risk) {
			risk = portInfo.Risk
		}

		if portInfo.Risk == model.RiskHigh {
			reasons = append(reasons, fmt.Sprintf(
				"Port %d/%s: %s", port, portInfo.Protocol, portInfo.Description,
			))
			if category == model.CategoryUnknown {
				category = model.CategoryCamera
			}
			hasStreamingPort = true
			if port == 32100 || port == 8600 {
				hasP2PPort = true
			}
			if port == 23 || port == 9527 {
				hasBackdoor = true
			}
		} else if portInfo.Risk == model.RiskMedium {
			reasons = append(reasons, fmt.Sprintf(
				"Port %d/%s: %s", port, portInfo.Protocol, portInfo.Description,
			))
		}

		if portInfo.WebOpenable {
			hasWebInterface = true
		}
	}

	// 4. Chipset vendor + camera ports = likely hidden camera
	if isGenericChipsetVendor(device.Vendor) && hasStreamingPort {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons, fmt.Sprintf(
			"Generic WiFi chipset (%s) with camera ports open — "+
				"likely a hidden/spy camera using a commodity WiFi module "+
				"(Anyka, Ingenic, or Goke SoC)",
			device.Vendor,
		))
	}

	// 5. P2P port is an extremely strong hidden camera indicator
	if hasP2PPort {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons,
			"P2P cloud protocol detected — this is the primary communication "+
				"method for hidden spy cameras. The device streams video to a cloud "+
				"relay server rather than exposing local RTSP",
		)
	}

	// 6. Telnet/debug backdoor on IoT device = cheap camera
	if hasBackdoor && (category == model.CategoryIOT || category == model.CategoryUnknown) {
		hasMediaPort := false
		for _, p := range device.OpenPorts {
			if p == 554 || p == 8554 || p == 10554 || p == 80 || p == 81 || p == 32100 {
				hasMediaPort = true
				break
			}
		}
		if hasMediaPort {
			risk = model.RiskHigh
			category = model.CategoryCamera
			reasons = append(reasons,
				"Debug backdoor + media ports on unknown device — strong indicator "+
					"of a cheap Chinese IP camera with default firmware",
			)
		}
	}

	// 7. Combined signal: camera manufacturer + web interface = admin panel
	if category == model.CategoryCamera && hasWebInterface && !hasStreamingPort {
		reasons = append(reasons,
			"Web interface detected on a camera device — likely an admin panel "+
				"where you can view live feeds or change settings",
		)
	}

	// 8. Combined signal: streaming port + web interface = very likely camera
	if hasStreamingPort && hasWebInterface {
		reasons = append(reasons,
			"Both streaming protocol and web interface detected — "+
				"strong indicator of an active IP camera",
		)
	}

	device.RiskLevel = risk
	device.Category = category
	device.RiskReasons = reasons
	device.ScanComplete = true
}

func riskPriority(r model.RiskLevel) int {
	switch r {
	case model.RiskHigh:
		return 3
	case model.RiskMedium:
		return 2
	case model.RiskLow:
		return 1
	default:
		return 0
	}
}

func isGenericChipsetVendor(vendor string) bool {
	if vendor == "" || vendor == "Unknown" {
		return false
	}
	v := strings.ToLower(vendor)
	for _, chip := range chipsetVendors {
		if strings.Contains(v, chip) {
			return true
		}
	}
	return false
}

func isKnownSafeVendor(vendor string) bool {
	if vendor == "" || vendor == "Unknown" {
		return false
	}
	v := strings.ToLower(vendor)
	for _, safe := range safeVendors {
		if strings.Contains(v, safe) {
			return true
		}
	}
	return false
}
