package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/cuz/safestay/internal/model"
)

func TestBeginScanClearsExistingResults(t *testing.T) {
	app := NewApp("test")
	app.subnet = "192.168.1.0/24"
	app.width = 100
	app.height = 24
	app.recalcLayout()

	device := &model.Device{
		IP:           "192.168.1.20",
		MAC:          "AA:BB:CC:DD:EE:FF",
		Vendor:       "Camera Vendor",
		OpenPorts:    []int{80},
		ScanComplete: true,
	}
	app.devices[device.MAC] = device
	app.table.AddDevice(device)
	app.detailDevice = device
	app.notification = "stale"

	app.beginScan()

	if !app.scanning {
		t.Fatal("expected scanning to be true")
	}
	if got := len(app.devices); got != 0 {
		t.Fatalf("expected devices to be cleared, got %d", got)
	}
	if app.detailDevice != nil {
		t.Fatal("expected detailDevice to be cleared")
	}
	if app.table.SelectedDevice() != nil {
		t.Fatal("expected table selection to be cleared")
	}
	if !strings.Contains(app.emptyMessage, "Discovering devices on 192.168.1.0/24") {
		t.Fatalf("unexpected empty message: %q", app.emptyMessage)
	}
	if app.notification != "" {
		t.Fatalf("expected notification to be cleared, got %q", app.notification)
	}
}

func TestRecalcLayoutSwitchesBetweenCompactAndSplit(t *testing.T) {
	app := NewApp("test")
	app.width = 80
	app.height = 24
	app.recalcLayout()

	if !app.compact {
		t.Fatal("expected compact layout for narrow window")
	}
	if got := app.detailPaneW; got != 80 {
		t.Fatalf("unexpected compact detail width: got %d want 80", got)
	}
	if got := app.table.width; got != 80 {
		t.Fatalf("unexpected compact table width: got %d want 80", got)
	}

	app.width = 120
	app.height = 24
	app.recalcLayout()

	if app.compact {
		t.Fatal("expected split layout for wide window")
	}
	if got := app.table.width + app.detailPaneW; got != 120 {
		t.Fatalf("split layout should fill width: got %d want 120", got)
	}
}

func TestViewFitsTerminalWidthInCompactAndSplitLayouts(t *testing.T) {
	device := &model.Device{
		IP:           "192.168.1.42",
		MAC:          "AA:BB:CC:DD:EE:42",
		Vendor:       "Example Vendor Name That Is Long Enough To Truncate",
		OpenPorts:    []int{80, 554},
		RiskLevel:    model.RiskHigh,
		Category:     model.CategoryCamera,
		RiskReasons:  []string{"Streaming protocol and admin panel detected on the same device."},
		ScanComplete: true,
	}

	for _, width := range []int{80, 120} {
		app := NewApp("test")
		app.width = width
		app.height = 24
		app.recalcLayout()
		app.devices[device.MAC] = device
		app.table.AddDevice(device)
		app.updateDetail()

		view := app.View()
		lines := strings.Split(view, "\n")
		if len(lines) > app.height {
			t.Fatalf("view exceeded window height for width %d: got %d lines want <= %d", width, len(lines), app.height)
		}
		for i, line := range lines {
			if got := lipgloss.Width(line); got > width {
				t.Fatalf("line %d exceeded width %d: got %d", i, width, got)
			}
		}
	}
}

func TestRenderStatusBarFillsFullWidthAfterScan(t *testing.T) {
	app := NewApp("test")
	app.width = 100
	app.statusCounts = &scanCounts{
		Total:  10,
		High:   0,
		Medium: 0,
		Low:    10,
	}

	line := app.renderStatusBar()
	if got, want := lipgloss.Width(line), 100; got != want {
		t.Fatalf("status bar width mismatch: got %d want %d", got, want)
	}

	if !strings.Contains(line, "HIGH: 0") || !strings.Contains(line, "LOW: 10") {
		t.Fatalf("expected summary counts in status bar, got %q", line)
	}
}
