package fingerprint

import (
	"fmt"
	"strings"

	"abdeen.dev/safestay/internal/model"
	"abdeen.dev/safestay/internal/oui"
)

// chipsetVendors are vendor strings indicating a generic WiFi / SoC module
// that does not in itself identify a product class. These show up on the
// inside of unbranded Tuya/AliExpress hidden cameras far more often than on
// any major-brand consumer device, so we treat them as suspicious context
// rather than a benign fingerprint.
var chipsetVendors = []string{
	"realtek", "ralink", "mediatek", "espressif", "hisilicon",
	"anyka", "ingenic", "goke", "xiongmai", "tuya",
	"wifi module", "wireless", "semiconductor",
}

// safeVendors are major consumer-electronics brands we trust to be what they
// claim. A camera-suspect port on one of these is typically a legitimate
// service (AirPlay, smart-TV control) rather than a hidden camera.
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

// consumerCameraBrands lists known-brand cameras whose presence in a listing
// must be disclosed by the host. SafeStay still flags them HIGH (the user
// needs to know they exist) but adds context that this may be a doorbell or
// outdoor camera the host already disclosed in the listing.
var consumerCameraBrands = []string{
	"ring", "nest", "wyze", "arlo", "eufy", "tp-link/tapo", "tapo",
}

// LookupVendor sets the vendor name on a device using 3-tier lookup.
func LookupVendor(device *model.Device) {
	if brand := oui.LookupOUIPrefix(device.MAC); brand != "" {
		device.Vendor = brand
		return
	}
	if chipset := oui.LookupChipsetPrefix(device.MAC); chipset != "" {
		device.Vendor = chipset
		return
	}
	if vendor := oui.LookupFallback(device.MAC); vendor != "" {
		device.Vendor = vendor
		return
	}
	device.Vendor = "Unknown"
}

// FingerprintDevice analyses a device and assigns risk level, category, and
// human-readable reasons. The model is intentionally biased toward false
// positives for unknown vendors: a "Tuya/Anyka/Unknown" device that responds
// on camera ports is exactly the modern hostile-host threat, even though no
// OUI database will ever list it.
func FingerprintDevice(device *model.Device) {
	var reasons []string
	risk := model.RiskLow
	category := model.CategoryUnknown

	brand := oui.LookupOUIPrefix(device.MAC)
	chipset := oui.LookupChipsetPrefix(device.MAC)

	// 1. Known camera brand by OUI — HIGH.
	if brand != "" {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons, fmt.Sprintf(
			"MAC prefix matches known camera manufacturer: %s (OUI %s)",
			brand, strings.ToUpper(device.MAC[:8]),
		))
		if isConsumerCameraBrand(brand) {
			reasons = append(reasons,
				"This is a major consumer-camera brand. Hosts are required by Airbnb "+
					"to disclose any camera in the listing — check the listing page. "+
					"An outdoor doorbell or outside-only camera may be legitimate; any "+
					"camera inside the unit has been prohibited since April 2024.",
			)
		}
	} else if chipset != "" {
		risk = model.RiskMedium
		category = model.CategoryIOT
		reasons = append(reasons, fmt.Sprintf(
			"WiFi/SoC vendor: %s (OUI %s) — commonly found inside unbranded "+
				"hidden cameras built on commodity modules, but also in many "+
				"legitimate IoT devices",
			chipset, strings.ToUpper(device.MAC[:8]),
		))
	}

	// 2. Vendor-name keyword match (covers vendors not in our OUI list).
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

	// 3. Open-port analysis.
	isSafeVendor := isKnownSafeVendor(device.Vendor)
	hasStreamingPort := false
	hasWebInterface := false
	hasP2PPort := false
	hasBackdoor := false
	suspectPortCount := 0

	for _, port := range device.OpenPorts {
		portInfo, ok := model.PortDatabase[port]
		if !ok {
			continue
		}

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
			suspectPortCount++
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
			suspectPortCount++
		}

		if portInfo.WebOpenable {
			hasWebInterface = true
		}
	}

	// 4. Generic chipset / commodity SoC + camera ports — almost always a
	// hidden camera built on a Tuya, Anyka, Ingenic or Goke module.
	if isGenericChipsetVendor(device.Vendor) && hasStreamingPort {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons, fmt.Sprintf(
			"Generic WiFi/SoC chipset (%s) with camera ports open — "+
				"strong indicator of a hidden/spy camera built on a commodity "+
				"module (Tuya, Anyka, Ingenic, or Goke SoC)",
			device.Vendor,
		))
	}

	// 5. Unknown vendor that responds on multiple camera-suspect ports.
	// This is the modern threat profile: an unbranded AliExpress module with
	// a randomised or unregistered MAC that does not appear in any OUI list,
	// running stock firmware that opens a web UI and a streaming port. The
	// old logic only flagged this if a specifically-HIGH port (e.g. 554) was
	// open; we now upgrade on the pattern itself.
	if isUnknownVendor(device.Vendor) {
		if hasStreamingPort {
			risk = model.RiskHigh
			category = model.CategoryCamera
			reasons = append(reasons,
				"Unrecognised vendor responding on a streaming protocol port — "+
					"hostile cameras increasingly ship with random or unregistered "+
					"MAC addresses precisely so they don't appear in vendor "+
					"databases. Treat this as a likely camera, not an unknown.",
			)
		} else if suspectPortCount >= 2 {
			if riskPriority(model.RiskMedium) > riskPriority(risk) {
				risk = model.RiskMedium
			}
			if category == model.CategoryUnknown {
				category = model.CategoryIOT
			}
			reasons = append(reasons,
				"Unrecognised vendor with multiple camera-suspect ports open — "+
					"this device responds to several probes that most consumer "+
					"electronics ignore. Worth a physical check.",
			)
		}
	}

	// 6. P2P / cloud relay port is an extremely strong hidden-camera indicator.
	if hasP2PPort {
		risk = model.RiskHigh
		category = model.CategoryCamera
		reasons = append(reasons,
			"P2P cloud protocol detected — this is the primary communication "+
				"method for hidden spy cameras. The device streams video to a "+
				"cloud relay server rather than exposing local RTSP, which is "+
				"specifically how an unbranded camera hides from local scans",
		)
	}

	// 7. Telnet / debug backdoor on an IoT-class device alongside media ports.
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

	// 8. Helpful combined-signal notes.
	if category == model.CategoryCamera && hasWebInterface && !hasStreamingPort {
		reasons = append(reasons,
			"Web interface detected on a camera device — likely an admin panel "+
				"where you can view live feeds or change settings",
		)
	}
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

func isUnknownVendor(vendor string) bool {
	return vendor == "" || strings.EqualFold(vendor, "Unknown")
}

func isConsumerCameraBrand(brand string) bool {
	b := strings.ToLower(brand)
	for _, name := range consumerCameraBrands {
		if strings.Contains(b, name) {
			return true
		}
	}
	return false
}
