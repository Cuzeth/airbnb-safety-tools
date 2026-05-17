package fingerprint

import (
	"strings"
	"testing"

	"abdeen.dev/safestay/internal/model"
)

func TestUnknownVendorWithStreamingPortIsHigh(t *testing.T) {
	device := &model.Device{
		IP:        "192.168.1.50",
		MAC:       "AA:BB:CC:DD:EE:FF",
		Vendor:    "Unknown",
		OpenPorts: []int{554},
	}
	FingerprintDevice(device)

	if device.RiskLevel != model.RiskHigh {
		t.Fatalf("expected HIGH for unknown+RTSP, got %s", device.RiskLevel)
	}
	if device.Category != model.CategoryCamera {
		t.Fatalf("expected Camera category, got %s", device.Category)
	}
	if !containsReason(device.RiskReasons, "Unrecognised vendor") {
		t.Fatalf("expected the unrecognised-vendor reason in %v", device.RiskReasons)
	}
}

func TestUnknownVendorWithMultipleSuspectPortsIsMedium(t *testing.T) {
	device := &model.Device{
		IP:        "192.168.1.51",
		MAC:       "AA:BB:CC:DD:EE:00",
		Vendor:    "Unknown",
		OpenPorts: []int{80, 8080},
	}
	FingerprintDevice(device)

	if device.RiskLevel != model.RiskMedium {
		t.Fatalf("expected MEDIUM for unknown+2 medium ports, got %s", device.RiskLevel)
	}
}

func TestKnownConsumerCameraGetsDisclosureNote(t *testing.T) {
	device := &model.Device{
		IP:        "192.168.1.10",
		MAC:       "2C:AA:8E:11:22:33", // Wyze prefix
		Vendor:    "Wyze",
		OpenPorts: []int{},
	}
	FingerprintDevice(device)

	if device.RiskLevel != model.RiskHigh {
		t.Fatalf("expected HIGH for consumer camera brand, got %s", device.RiskLevel)
	}
	if !containsReason(device.RiskReasons, "Hosts are required by Airbnb") {
		t.Fatalf("expected disclosure note for consumer camera brand, got %v", device.RiskReasons)
	}
}

func TestTuyaChipsetWithStreamingPortIsHidden(t *testing.T) {
	device := &model.Device{
		IP:        "192.168.1.42",
		MAC:       "AA:BB:CC:DD:EE:FE",
		Vendor:    "Tuya Smart",
		OpenPorts: []int{6668, 8883},
	}
	FingerprintDevice(device)

	if device.RiskLevel != model.RiskHigh {
		t.Fatalf("expected HIGH for Tuya+P2P+MQTT, got %s", device.RiskLevel)
	}
	if device.Category != model.CategoryCamera {
		t.Fatalf("expected Camera category for Tuya P2P device, got %s", device.Category)
	}
}

func TestApplePhoneWithBenignPortStaysLow(t *testing.T) {
	device := &model.Device{
		IP:        "192.168.1.100",
		MAC:       "AA:BB:CC:DD:EE:01",
		Vendor:    "Apple, Inc.",
		OpenPorts: []int{5000, 3478},
	}
	FingerprintDevice(device)

	if device.RiskLevel != model.RiskLow {
		t.Fatalf("expected LOW for Apple device with AirPlay/STUN, got %s", device.RiskLevel)
	}
}

func containsReason(reasons []string, fragment string) bool {
	for _, r := range reasons {
		if strings.Contains(r, fragment) {
			return true
		}
	}
	return false
}
