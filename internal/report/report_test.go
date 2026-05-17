package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"abdeen.dev/safestay/internal/model"
)

func testDevices() []*model.Device {
	return []*model.Device{
		{
			IP: "192.168.1.100", MAC: "48:57:02:AA:BB:CC",
			Vendor: "Hikvision Digital Technology", Category: model.CategoryCamera,
			RiskLevel: model.RiskHigh, OpenPorts: []int{554, 80, 8000},
			RiskReasons:  []string{"Known camera manufacturer (Hikvision)", "RTSP port open (554)"},
			ScanComplete: true,
		},
		{
			IP: "192.168.1.50", MAC: "00:E0:4C:11:22:33",
			Vendor: "Realtek Semiconductor", Category: model.CategoryIOT,
			RiskLevel: model.RiskMedium, OpenPorts: []int{80},
			RiskReasons:  []string{"WiFi chipset commonly found in cameras"},
			ScanComplete: true,
		},
		{
			IP: "192.168.1.1", MAC: "00:1A:2B:33:44:55",
			Vendor: "Cisco Systems", Category: model.CategoryRouter,
			RiskLevel: model.RiskLow, OpenPorts: []int{80, 443},
			ScanComplete: true,
		},
		{
			IP: "192.168.1.200", MAC: "AA:BB:CC:DD:EE:FF",
			Vendor: "Unknown", Category: model.CategoryUnknown,
			RiskLevel: model.RiskLow,
			ScanComplete: true,
		},
	}
}

func TestGenerateCreatesFiles(t *testing.T) {
	devices := testDevices()

	path, err := Generate(devices, "192.168.1.0/24", "v1.0.0-test")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)

	jsonPath := strings.TrimSuffix(path, ".html") + ".json"
	defer os.Remove(jsonPath)

	if !strings.HasPrefix(path, "safestay-report-") || !strings.HasSuffix(path, ".html") {
		t.Errorf("unexpected HTML path: %s", path)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("HTML file not created: %s", path)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Fatalf("JSON file not created: %s", jsonPath)
	}
}

func TestHTMLContainsDevices(t *testing.T) {
	devices := testDevices()

	path, err := Generate(devices, "192.168.1.0/24", "v1.0.0-test")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(strings.TrimSuffix(path, ".html") + ".json")

	html, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}

	content := string(html)

	for _, want := range []string{
		"192.168.1.100",
		"192.168.1.50",
		"192.168.1.1",
		"Hikvision Digital Technology",
		"Realtek Semiconductor",
		"Cisco Systems",
		"192.168.1.0/24",
		"HIGH-risk device",
		"Flagged Devices",
		"RTSP port open",
		"Physical Check",
		"Not legal advice",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("HTML missing expected content: %q", want)
		}
	}
}

func TestHTMLHighRiskAlert(t *testing.T) {
	high := []*model.Device{
		{
			IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:FF",
			Vendor: "Dahua", Category: model.CategoryCamera,
			RiskLevel: model.RiskHigh, ScanComplete: true,
		},
	}

	path, err := Generate(high, "10.0.0.0/24", "test")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(strings.TrimSuffix(path, ".html") + ".json")

	html, _ := os.ReadFile(path)
	if !strings.Contains(string(html), "1 HIGH-risk device detected") {
		t.Error("expected high risk alert banner")
	}
	if !strings.Contains(string(html), "headline-alert") {
		t.Error("expected alert headline class")
	}
}

func TestHTMLAllClear(t *testing.T) {
	safe := []*model.Device{
		{
			IP: "10.0.0.1", MAC: "AA:BB:CC:DD:EE:FF",
			Vendor: "Apple", Category: model.CategoryPhone,
			RiskLevel: model.RiskLow, ScanComplete: true,
		},
	}

	path, err := Generate(safe, "10.0.0.0/24", "test")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(strings.TrimSuffix(path, ".html") + ".json")

	html, _ := os.ReadFile(path)
	if !strings.Contains(string(html), "No high-risk devices detected") {
		t.Error("expected all-clear banner")
	}
	if !strings.Contains(string(html), "headline-clear") {
		t.Error("expected clear headline class")
	}
}

func TestHTMLIsolationWarning(t *testing.T) {
	devices := []*model.Device{
		{IP: "10.0.0.1", MAC: "AA", Vendor: "Router", RiskLevel: model.RiskLow, ScanComplete: true},
	}

	path, err := GenerateWithReliability(devices, "10.0.0.0/24", "test", model.ReliabilityIsolated)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(strings.TrimSuffix(path, ".html") + ".json")

	html, _ := os.ReadFile(path)
	content := string(html)
	for _, want := range []string{
		"Scan was unreliable",
		"headline-warn",
		"AP / client isolation",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("isolation report missing %q", want)
		}
	}
}

func TestJSONStructure(t *testing.T) {
	devices := testDevices()

	path, err := Generate(devices, "192.168.1.0/24", "v1.0.0-test")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer os.Remove(path)

	jsonPath := strings.TrimSuffix(path, ".html") + ".json"
	defer os.Remove(jsonPath)

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(data, &jr); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if jr.Version != "v1.0.0-test" {
		t.Errorf("version = %q, want %q", jr.Version, "v1.0.0-test")
	}
	if jr.Network != "192.168.1.0/24" {
		t.Errorf("network = %q, want %q", jr.Network, "192.168.1.0/24")
	}
	if jr.Summary.Total != 4 {
		t.Errorf("total = %d, want 4", jr.Summary.Total)
	}
	if jr.Summary.High != 1 {
		t.Errorf("high = %d, want 1", jr.Summary.High)
	}
	if jr.Summary.Medium != 1 {
		t.Errorf("medium = %d, want 1", jr.Summary.Medium)
	}
	if jr.Summary.Low != 2 {
		t.Errorf("low = %d, want 2", jr.Summary.Low)
	}
	if len(jr.Devices) != 4 {
		t.Fatalf("devices = %d, want 4", len(jr.Devices))
	}

	// Devices should be sorted: HIGH first, then MEDIUM, then LOW
	if jr.Devices[0].RiskLevel != "high" {
		t.Errorf("first device risk = %q, want high", jr.Devices[0].RiskLevel)
	}
	if jr.Devices[1].RiskLevel != "medium" {
		t.Errorf("second device risk = %q, want medium", jr.Devices[1].RiskLevel)
	}
}

func TestSortDevicesOrder(t *testing.T) {
	devices := []*model.Device{
		{IP: "192.168.1.10", MAC: "AA", RiskLevel: model.RiskLow},
		{IP: "192.168.1.5", MAC: "BB", RiskLevel: model.RiskHigh},
		{IP: "192.168.1.2", MAC: "CC", RiskLevel: model.RiskMedium},
		{IP: "192.168.1.1", MAC: "DD", RiskLevel: model.RiskHigh},
	}

	sorted := sortDevices(devices)

	// HIGH devices first, sorted by IP numerically
	if sorted[0].IP != "192.168.1.1" {
		t.Errorf("sorted[0] = %s, want 192.168.1.1", sorted[0].IP)
	}
	if sorted[1].IP != "192.168.1.5" {
		t.Errorf("sorted[1] = %s, want 192.168.1.5", sorted[1].IP)
	}
	// Then MEDIUM
	if sorted[2].IP != "192.168.1.2" {
		t.Errorf("sorted[2] = %s, want 192.168.1.2", sorted[2].IP)
	}
	// Then LOW
	if sorted[3].IP != "192.168.1.10" {
		t.Errorf("sorted[3] = %s, want 192.168.1.10", sorted[3].IP)
	}
}

func TestGenerateEmptyDevices(t *testing.T) {
	path, err := Generate(nil, "10.0.0.0/24", "test")
	if err != nil {
		t.Fatalf("Generate failed on empty: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(strings.TrimSuffix(path, ".html") + ".json")

	html, _ := os.ReadFile(path)
	if !strings.Contains(string(html), "No high-risk devices detected") {
		t.Error("expected all-clear for empty scan")
	}
	if !strings.Contains(string(html), "0") {
		t.Error("expected zero count")
	}
}
