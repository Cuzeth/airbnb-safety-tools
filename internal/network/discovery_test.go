package network

import (
	"testing"

	"abdeen.dev/safestay/internal/model"
)

func TestAssessReliabilityIsolatedWhenEmpty(t *testing.T) {
	got := assessReliability(nil, "192.168.1.1", "192.168.1.42")
	if got != model.ReliabilityIsolated {
		t.Fatalf("empty scan should be isolated, got %s", got)
	}
}

func TestAssessReliabilityIsolatedWhenOnlyInfra(t *testing.T) {
	devices := []*model.Device{
		{IP: "192.168.1.1"},  // gateway
		{IP: "192.168.1.42"}, // self
	}
	got := assessReliability(devices, "192.168.1.1", "192.168.1.42")
	if got != model.ReliabilityIsolated {
		t.Fatalf("only gateway+self should be isolated, got %s", got)
	}
}

func TestAssessReliabilityPartialWhenFew(t *testing.T) {
	devices := []*model.Device{
		{IP: "192.168.1.1"},
		{IP: "192.168.1.99"},
	}
	got := assessReliability(devices, "192.168.1.1", "192.168.1.42")
	if got != model.ReliabilityPartial {
		t.Fatalf("two devices (one non-infra) should be partial, got %s", got)
	}
}

func TestAssessReliabilityNormal(t *testing.T) {
	devices := []*model.Device{
		{IP: "192.168.1.1"},
		{IP: "192.168.1.5"},
		{IP: "192.168.1.10"},
		{IP: "192.168.1.42"},
	}
	got := assessReliability(devices, "192.168.1.1", "192.168.1.42")
	if got != model.ReliabilityNormal {
		t.Fatalf("populated scan should be normal, got %s", got)
	}
}

func TestGuessGatewayDefaultsToDotOne(t *testing.T) {
	if got := guessGateway("10.0.4.0/24"); got != "10.0.4.1" {
		t.Fatalf("guessGateway(10.0.4.0/24) = %s, want 10.0.4.1", got)
	}
}

func TestSubnetPrefix(t *testing.T) {
	if got := subnetPrefix("192.168.1.0/24"); got != "192.168.1." {
		t.Fatalf("subnetPrefix = %q, want 192.168.1.", got)
	}
}
