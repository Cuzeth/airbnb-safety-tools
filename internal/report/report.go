package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"abdeen.dev/safestay/internal/model"
)

// ── HTML template data types ────────────────────────────────────────

type reportData struct {
	AppVersion string
	ScanTime   string
	ScanDate   string
	Subnet     string
	Summary    summaryData
	Devices    []deviceData
	Flagged    []deviceData
	HasFlagged bool
	HasHigh    bool
	HighCount  int
}

type summaryData struct {
	Total  int
	High   int
	Medium int
	Low    int
}

type deviceData struct {
	IP           string
	MAC          string
	Vendor       string
	Category     string
	RiskLevel    string
	RiskClass    string // "high", "medium", "low"
	OpenPorts    []portData
	PortsSummary string
	RiskReasons  []string
	HasPorts     bool
	HasReasons   bool
}

type portData struct {
	Port        int
	Protocol    string
	Description string
	RiskClass   string
}

// ── JSON export types ───────────────────────────────────────────────

type jsonReport struct {
	Version  string       `json:"safestay_version"`
	ScanTime string       `json:"scan_time"`
	Network  string       `json:"network"`
	Summary  jsonSummary  `json:"summary"`
	Devices  []jsonDevice `json:"devices"`
}

type jsonSummary struct {
	Total  int `json:"total"`
	High   int `json:"high_risk"`
	Medium int `json:"medium_risk"`
	Low    int `json:"low_risk"`
}

type jsonDevice struct {
	IP          string     `json:"ip"`
	MAC         string     `json:"mac"`
	Vendor      string     `json:"vendor"`
	Category    string     `json:"category"`
	RiskLevel   string     `json:"risk_level"`
	OpenPorts   []jsonPort `json:"open_ports,omitempty"`
	RiskReasons []string   `json:"risk_reasons,omitempty"`
}

type jsonPort struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// Generate creates an HTML report and companion JSON from scan results.
// Returns the path to the generated HTML file.
func Generate(devices []*model.Device, subnet, version string) (string, error) {
	now := time.Now()

	data := buildReportData(devices, subnet, version, now)

	htmlPath := fmt.Sprintf("safestay-report-%s.html", now.Format("2006-01-02-150405"))
	if err := writeHTML(data, htmlPath); err != nil {
		return "", fmt.Errorf("write HTML: %w", err)
	}

	// Best-effort JSON companion file.
	jsonPath := strings.TrimSuffix(htmlPath, ".html") + ".json"
	_ = writeJSON(data, devices, subnet, version, now, jsonPath)

	return htmlPath, nil
}

func buildReportData(devices []*model.Device, subnet, version string, now time.Time) reportData {
	sorted := sortDevices(devices)

	var high, medium, low int
	var devs []deviceData
	var flagged []deviceData

	for _, d := range sorted {
		dd := toDeviceData(d)
		devs = append(devs, dd)

		switch d.RiskLevel {
		case model.RiskHigh:
			high++
			flagged = append(flagged, dd)
		case model.RiskMedium:
			medium++
			flagged = append(flagged, dd)
		default:
			low++
		}
	}

	return reportData{
		AppVersion: version,
		ScanTime:   now.Format("January 2, 2006 at 3:04 PM MST"),
		ScanDate:   now.Format("2006-01-02"),
		Subnet:     subnet,
		Summary: summaryData{
			Total:  len(sorted),
			High:   high,
			Medium: medium,
			Low:    low,
		},
		Devices:    devs,
		Flagged:    flagged,
		HasFlagged: len(flagged) > 0,
		HasHigh:    high > 0,
		HighCount:  high,
	}
}

func toDeviceData(d *model.Device) deviceData {
	riskClass := strings.ToLower(string(d.RiskLevel))
	if riskClass == "" || riskClass == "unknown" {
		riskClass = "low"
	}

	var ports []portData
	var portNums []string
	for _, p := range d.OpenPorts {
		info, ok := model.PortDatabase[p]
		if ok {
			ports = append(ports, portData{
				Port:        p,
				Protocol:    info.Protocol,
				Description: info.Description,
				RiskClass:   strings.ToLower(string(info.Risk)),
			})
		} else {
			ports = append(ports, portData{
				Port:     p,
				Protocol: "TCP",
			})
		}
		portNums = append(portNums, fmt.Sprintf("%d", p))
	}

	summary := "-"
	if len(portNums) > 0 {
		summary = strings.Join(portNums, ", ")
	}

	return deviceData{
		IP:           d.IP,
		MAC:          d.MAC,
		Vendor:       d.Vendor,
		Category:     string(d.Category),
		RiskLevel:    d.RiskLevel.Label(),
		RiskClass:    riskClass,
		OpenPorts:    ports,
		PortsSummary: summary,
		RiskReasons:  d.RiskReasons,
		HasPorts:     len(ports) > 0,
		HasReasons:   len(d.RiskReasons) > 0,
	}
}

// sortDevices returns a copy sorted by risk (HIGH first), then by IP.
func sortDevices(devices []*model.Device) []*model.Device {
	sorted := make([]*model.Device, len(devices))
	copy(sorted, devices)

	sort.Slice(sorted, func(i, j int) bool {
		ri, rj := riskOrder(sorted[i].RiskLevel), riskOrder(sorted[j].RiskLevel)
		if ri != rj {
			return ri < rj
		}
		return compareIPs(sorted[i].IP, sorted[j].IP)
	})

	return sorted
}

func riskOrder(r model.RiskLevel) int {
	switch r {
	case model.RiskHigh:
		return 0
	case model.RiskMedium:
		return 1
	case model.RiskLow:
		return 2
	default:
		return 3
	}
}

func compareIPs(a, b string) bool {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil || ipB == nil {
		return a < b
	}
	v4A, v4B := ipA.To4(), ipB.To4()
	if v4A == nil || v4B == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if v4A[i] != v4B[i] {
			return v4A[i] < v4B[i]
		}
	}
	return false
}

func writeHTML(data reportData, path string) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func writeJSON(data reportData, devices []*model.Device, subnet, version string, now time.Time, path string) error {
	sorted := sortDevices(devices)

	var jDevices []jsonDevice
	for _, d := range sorted {
		jd := jsonDevice{
			IP:          d.IP,
			MAC:         d.MAC,
			Vendor:      d.Vendor,
			Category:    string(d.Category),
			RiskLevel:   string(d.RiskLevel),
			RiskReasons: d.RiskReasons,
		}
		for _, p := range d.OpenPorts {
			jp := jsonPort{Port: p, Protocol: "TCP", Risk: "low"}
			if info, ok := model.PortDatabase[p]; ok {
				jp.Protocol = info.Protocol
				jp.Description = info.Description
				jp.Risk = string(info.Risk)
			}
			jd.OpenPorts = append(jd.OpenPorts, jp)
		}
		jDevices = append(jDevices, jd)
	}

	jr := jsonReport{
		Version:  version,
		ScanTime: now.Format(time.RFC3339),
		Network:  subnet,
		Summary: jsonSummary{
			Total:  data.Summary.Total,
			High:   data.Summary.High,
			Medium: data.Summary.Medium,
			Low:    data.Summary.Low,
		},
		Devices: jDevices,
	}

	raw, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, raw, 0644)
}

// ── HTML template ───────────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeStay Report &mdash; {{.ScanDate}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;background:#F8FAFC;color:#334155;line-height:1.6;-webkit-font-smoothing:antialiased}
.header{background:linear-gradient(135deg,#0F172A 0%,#1E293B 100%);color:#F8FAFC;padding:2rem 2.5rem}
.header h1{font-size:1.75rem;font-weight:700;letter-spacing:-.025em}
.header .meta{color:#94A3B8;margin-top:.5rem;font-size:.9rem}
.header .meta span{color:#38BDF8;font-weight:600}
.container{max-width:1100px;margin:0 auto;padding:2rem 2.5rem}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.summary-card{background:#fff;border-radius:.5rem;padding:1.25rem;text-align:center;border-top:3px solid;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.summary-card .count{font-size:2rem;font-weight:700;line-height:1.2}
.summary-card .label{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
.card-total{border-color:#38BDF8}.card-total .count{color:#0F172A}.card-total .label{color:#64748B}
.card-high{border-color:#EF4444}.card-high .count{color:#B91C1C}.card-high .label{color:#991B1B}
.card-medium{border-color:#F59E0B}.card-medium .count{color:#B45309}.card-medium .label{color:#92400E}
.card-low{border-color:#22C55E}.card-low .count{color:#15803D}.card-low .label{color:#166534}
.alert{background:#FEF2F2;border:1px solid #FECACA;border-left:4px solid #EF4444;border-radius:.5rem;padding:1rem 1.25rem;margin-bottom:2rem;color:#991B1B;font-weight:600;font-size:.95rem}
.all-clear{background:#F0FDF4;border:1px solid #BBF7D0;border-left:4px solid #22C55E;border-radius:.5rem;padding:1rem 1.25rem;margin-bottom:2rem;color:#166534;font-weight:600;font-size:.95rem}
h2{font-size:1.25rem;font-weight:700;color:#0F172A;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:2px solid #E2E8F0}
.table-wrap{overflow-x:auto;margin-bottom:2.5rem}
table{width:100%;border-collapse:collapse;font-size:.875rem}
thead th{background:#1E293B;color:#F8FAFC;font-weight:600;text-align:left;padding:.75rem 1rem;white-space:nowrap}
thead th:first-child{border-radius:.375rem 0 0 0}
thead th:last-child{border-radius:0 .375rem 0 0}
tbody td{padding:.625rem 1rem;border-bottom:1px solid #E2E8F0;vertical-align:top}
tbody tr:nth-child(even){background:#F8FAFC}
tbody tr:hover{background:#F1F5F9}
.badge{display:inline-block;padding:.2rem .6rem;border-radius:.25rem;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.badge-high{background:#991B1B;color:#FEF2F2}
.badge-medium{background:#D97706;color:#1C1917}
.badge-low{background:#166534;color:#F0FDF4}
.mono{font-family:'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;font-size:.85rem}
.device-card{background:#fff;border-radius:.5rem;margin-bottom:1.5rem;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid}
.device-card.risk-high{border-color:#EF4444}
.device-card.risk-medium{border-color:#F59E0B}
.card-header{padding:1rem 1.5rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #E2E8F0;flex-wrap:wrap;gap:.5rem}
.card-header h3{font-size:1rem;font-weight:600;color:#0F172A}
.card-body{padding:1.25rem 1.5rem}
.device-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem;margin-bottom:1.25rem}
.device-meta dt{font-size:.75rem;font-weight:600;color:#64748B;text-transform:uppercase;letter-spacing:.05em}
.device-meta dd{font-size:.9rem;color:#334155;margin-top:.125rem}
h4{font-size:.8rem;font-weight:700;color:#475569;margin:1.25rem 0 .5rem;text-transform:uppercase;letter-spacing:.05em}
.port-list{list-style:none}
.port-list li{padding:.5rem 0;border-bottom:1px solid #F1F5F9;font-size:.875rem}
.port-list li:last-child{border-bottom:none}
.port-num{font-weight:700;font-family:'SF Mono','Cascadia Code','Fira Code','Consolas',monospace}
.port-proto{font-weight:600;margin-left:.25rem}
.port-high .port-num,.port-high .port-proto{color:#B91C1C}
.port-medium .port-num,.port-medium .port-proto{color:#B45309}
.port-desc{display:block;color:#64748B;font-size:.8rem;margin-top:.125rem}
.reason-list{list-style:none}
.reason-list li{padding:.375rem 0;font-size:.875rem}
.reason-list li::before{content:"\2022";margin-right:.5rem;font-weight:700}
.reason-high li{color:#B91C1C}
.reason-medium li{color:#B45309}
.footer{margin-top:2.5rem;padding-top:1.5rem;border-top:2px solid #E2E8F0;text-align:center;font-size:.8rem;color:#94A3B8}
.footer p{margin-bottom:.5rem}
@media print{body{background:#fff}.header{break-after:avoid;-webkit-print-color-adjust:exact;print-color-adjust:exact}.device-card{break-inside:avoid}.summary{break-inside:avoid}thead th{-webkit-print-color-adjust:exact;print-color-adjust:exact}.badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media(max-width:768px){.summary{grid-template-columns:repeat(2,1fr)}.container{padding:1rem}.header{padding:1.5rem 1rem}.device-meta{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="header">
  <h1>SafeStay Scanner Report</h1>
  <p class="meta">Scanned <span>{{.ScanTime}}</span> on network <span>{{.Subnet}}</span></p>
</div>

<div class="container">

  <div class="summary">
    <div class="summary-card card-total">
      <div class="count">{{.Summary.Total}}</div>
      <div class="label">Devices</div>
    </div>
    <div class="summary-card card-high">
      <div class="count">{{.Summary.High}}</div>
      <div class="label">High Risk</div>
    </div>
    <div class="summary-card card-medium">
      <div class="count">{{.Summary.Medium}}</div>
      <div class="label">Medium Risk</div>
    </div>
    <div class="summary-card card-low">
      <div class="count">{{.Summary.Low}}</div>
      <div class="label">Low Risk</div>
    </div>
  </div>

  {{if .HasHigh -}}
  <div class="alert">
    &#9888; {{.HighCount}} HIGH RISK device{{if gt .HighCount 1}}s{{end}} detected &mdash; review the flagged devices below.
  </div>
  {{- else -}}
  <div class="all-clear">
    &#10003; No high-risk devices detected on this network.
  </div>
  {{- end}}

  <h2>All Devices</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>IP Address</th>
          <th>MAC Address</th>
          <th>Vendor</th>
          <th>Category</th>
          <th>Open Ports</th>
        </tr>
      </thead>
      <tbody>
        {{range .Devices -}}
        <tr>
          <td><span class="badge badge-{{.RiskClass}}">{{.RiskLevel}}</span></td>
          <td class="mono">{{.IP}}</td>
          <td class="mono">{{.MAC}}</td>
          <td>{{.Vendor}}</td>
          <td>{{.Category}}</td>
          <td class="mono">{{.PortsSummary}}</td>
        </tr>
        {{- end}}
      </tbody>
    </table>
  </div>

  {{if .HasFlagged -}}
  <h2>Flagged Devices</h2>
  {{range .Flagged -}}
  <div class="device-card risk-{{.RiskClass}}">
    <div class="card-header">
      <h3>{{.Vendor}} &mdash; {{.IP}}</h3>
      <span class="badge badge-{{.RiskClass}}">{{.RiskLevel}}</span>
    </div>
    <div class="card-body">
      <dl class="device-meta">
        <div><dt>IP Address</dt><dd class="mono">{{.IP}}</dd></div>
        <div><dt>MAC Address</dt><dd class="mono">{{.MAC}}</dd></div>
        <div><dt>Vendor</dt><dd>{{.Vendor}}</dd></div>
        <div><dt>Category</dt><dd>{{.Category}}</dd></div>
      </dl>

      {{if .HasPorts -}}
      <h4>Open Ports</h4>
      <ul class="port-list">
        {{range .OpenPorts -}}
        <li class="port-{{.RiskClass}}">
          <span class="port-num">{{.Port}}</span><span class="port-proto">/{{.Protocol}}</span>
          {{if .Description}}<span class="port-desc">{{.Description}}</span>{{end}}
        </li>
        {{- end}}
      </ul>
      {{- end}}

      {{if .HasReasons -}}
      <h4>Risk Analysis</h4>
      <ul class="reason-list reason-{{.RiskClass}}">
        {{range .RiskReasons -}}
        <li>{{.}}</li>
        {{- end}}
      </ul>
      {{- end}}
    </div>
  </div>
  {{- end}}
  {{- end}}

  <div class="footer">
    <p>Generated by <strong>SafeStay Scanner</strong> {{.AppVersion}}</p>
    <p>This report is for personal safety and informational purposes only. Always contact local authorities if you believe a crime has occurred.</p>
    <p>Do not scan networks without authorization. Results may contain false positives.</p>
  </div>

</div>
</body>
</html>`
