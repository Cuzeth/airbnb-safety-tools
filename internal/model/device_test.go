package model

import "testing"

func TestDeviceCloneDeepCopiesSlices(t *testing.T) {
	original := &Device{
		IP:           "192.168.1.10",
		MAC:          "AA:BB:CC:DD:EE:FF",
		Vendor:       "Test Vendor",
		OpenPorts:    []int{80, 554},
		RiskReasons:  []string{"original reason"},
		ScanComplete: true,
	}

	clone := original.Clone()
	if clone == nil {
		t.Fatal("expected clone, got nil")
	}
	if clone == original {
		t.Fatal("expected a distinct clone pointer")
	}

	clone.OpenPorts[0] = 443
	clone.RiskReasons[0] = "changed"

	if original.OpenPorts[0] != 80 {
		t.Fatalf("original OpenPorts mutated: got %d", original.OpenPorts[0])
	}
	if original.RiskReasons[0] != "original reason" {
		t.Fatalf("original RiskReasons mutated: got %q", original.RiskReasons[0])
	}
}
