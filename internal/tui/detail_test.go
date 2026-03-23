package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/cuz/safestay/internal/model"
)

func TestRenderDetailWrapsToPanelWidth(t *testing.T) {
	device := &model.Device{
		IP:           "10.155.175.214",
		MAC:          "60:3E:5F:84:BD:95",
		Vendor:       "Apple, Inc.",
		RiskLevel:    model.RiskLow,
		Category:     model.CategoryPhone,
		OpenPorts:    []int{5000},
		ScanComplete: true,
		RiskReasons: []string{
			"Port 5000/HTTP-NAS: AirPlay / smart device service (normal for Apple, Inc.)",
		},
	}

	view := renderDetail(device, 30)
	lines := strings.Split(view, "\n")
	for i, line := range lines {
		if got := lipgloss.Width(line); got > 30 {
			t.Fatalf("line %d exceeded width 30: got %d, line=%q", i, got, line)
		}
	}

	if !strings.Contains(view, "device") {
		t.Fatalf("expected wrapped detail content to include risk reason text, got %q", view)
	}
}
