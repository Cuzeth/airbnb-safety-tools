package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/cuz/safestay/internal/model"
)

// tableModel is a custom table rendered entirely with Lip Gloss.
type tableModel struct {
	devices    []*model.Device
	macToIndex map[string]int
	cursor     int
	offset     int // scroll offset for visible window
	width      int
	height     int // visible data rows (excluding header)
}

func newTableModel() tableModel {
	return tableModel{
		macToIndex: make(map[string]int),
	}
}

func (m *tableModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.clampScroll()
}

func (m *tableModel) Clear() {
	m.devices = nil
	m.macToIndex = make(map[string]int)
	m.cursor = 0
	m.offset = 0
}

func (m *tableModel) AddDevice(device *model.Device) {
	m.macToIndex[device.MAC] = len(m.devices)
	m.devices = append(m.devices, device)
}

func (m *tableModel) UpdateDevice(device *model.Device) {
	if idx, ok := m.macToIndex[device.MAC]; ok {
		m.devices[idx] = device
	}
}

func (m *tableModel) SelectedDevice() *model.Device {
	if m.cursor >= 0 && m.cursor < len(m.devices) {
		return m.devices[m.cursor]
	}
	return nil
}

func (m *tableModel) MoveUp() {
	if m.cursor > 0 {
		m.cursor--
		m.clampScroll()
	}
}

func (m *tableModel) MoveDown() {
	if m.cursor < len(m.devices)-1 {
		m.cursor++
		m.clampScroll()
	}
}

func (m *tableModel) clampScroll() {
	if m.height <= 0 {
		return
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.height {
		m.offset = m.cursor - m.height + 1
	}
}

// View renders the table as a fixed-width, fixed-height block of text.
// Output is exactly (m.height + 1) lines tall and m.width chars wide.
func (m *tableModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}

	w := m.width
	emptyRow := strings.Repeat(" ", w)

	// Column layout: fixed columns + flex columns, all fitting within w
	riskW, ipW, macW, vendorW, catW, portsW := m.columnWidths()

	// Header
	hdr := m.renderFixedRow(
		riskW, ipW, macW, vendorW, catW, portsW,
		"Risk", "IP Address", "MAC Address", "Vendor", "Category", "Ports",
		TableHeaderStyle,
	)

	var rows []string
	rows = append(rows, hdr)

	// Visible data rows
	visibleEnd := m.offset + m.height
	if visibleEnd > len(m.devices) {
		visibleEnd = len(m.devices)
	}

	for i := m.offset; i < visibleEnd; i++ {
		d := m.devices[i]
		isSelected := i == m.cursor

		var style lipgloss.Style
		if isSelected {
			style = TableSelectedStyle
		} else {
			style = lipgloss.NewStyle()
		}

		risk := riskBadgePlain(d.RiskLevel)
		ports := portsPlain(d)

		row := m.renderDataRow(
			riskW, ipW, macW, vendorW, catW, portsW,
			risk, d.IP, d.MAC, truncate(d.Vendor, vendorW), string(d.Category), ports,
			style, isSelected,
		)
		rows = append(rows, row)
	}

	// Pad with empty rows to fill height
	for len(rows) < m.height+1 {
		rows = append(rows, emptyRow)
	}

	return strings.Join(rows, "\n")
}

// columnWidths computes column widths that sum to m.width (including gaps).
func (m *tableModel) columnWidths() (int, int, int, int, int, int) {
	riskW := 10
	ipW := 16
	macW := 18
	catW := 14
	gaps := 5 // one space between each of the 6 columns

	fixed := riskW + ipW + macW + catW + gaps
	remaining := m.width - fixed
	if remaining < 10 {
		remaining = 10
	}
	vendorW := remaining * 55 / 100
	portsW := remaining - vendorW

	return riskW, ipW, macW, vendorW, catW, portsW
}

// renderFixedRow renders a header row padded/truncated to exactly m.width.
func (m *tableModel) renderFixedRow(riskW, ipW, macW, vendorW, catW, portsW int, risk, ip, mac, vendor, category, ports string, style lipgloss.Style) string {
	content := padRight(risk, riskW) + " " +
		padRight(ip, ipW) + " " +
		padRight(mac, macW) + " " +
		padRight(vendor, vendorW) + " " +
		padRight(category, catW) + " " +
		padRight(ports, portsW)
	return style.Width(m.width).MaxWidth(m.width).Render(content)
}

// renderDataRow renders a data row. The risk cell gets its own colored badge;
// the rest of the row uses the row style (plain or selected highlight).
func (m *tableModel) renderDataRow(riskW, ipW, macW, vendorW, catW, portsW int, risk, ip, mac, vendor, category, ports string, rowStyle lipgloss.Style, selected bool) string {
	// Build the risk badge (always colored, even when selected)
	riskCell := renderRiskCell(risk, riskW)

	// Build the rest of the row as plain text, then style it
	rest := padRight(ip, ipW) + " " +
		padRight(mac, macW) + " " +
		padRight(vendor, vendorW) + " " +
		padRight(category, catW) + " " +
		padRight(ports, portsW)

	restW := m.width - riskW - 1 // -1 for the gap after risk
	if restW < 1 {
		restW = 1
	}

	styledRest := rowStyle.Width(restW).MaxWidth(restW).Render(rest)
	line := riskCell + " " + styledRest

	// Ensure line is exactly m.width visible chars by padding or truncating
	vis := lipgloss.Width(line)
	if vis < m.width {
		line += strings.Repeat(" ", m.width-vis)
	}
	return line
}

func renderRiskCell(risk string, width int) string {
	padded := padCenter(risk, width)
	switch risk {
	case "HIGH":
		return HighRiskStyle.Width(width).MaxWidth(width).Render(padded)
	case "MEDIUM":
		return MediumRiskStyle.Width(width).MaxWidth(width).Render(padded)
	case "LOW":
		return LowRiskStyle.Width(width).MaxWidth(width).Render(padded)
	default:
		return UnknownRiskStyle.Width(width).MaxWidth(width).Render(padded)
	}
}

func riskBadgePlain(risk model.RiskLevel) string {
	switch risk {
	case model.RiskHigh:
		return "HIGH"
	case model.RiskMedium:
		return "MEDIUM"
	case model.RiskLow:
		return "LOW"
	default:
		return "?"
	}
}

func portsPlain(device *model.Device) string {
	if !device.ScanComplete {
		return "scanning..."
	}
	if len(device.OpenPorts) == 0 {
		return "-"
	}
	var parts []string
	for _, port := range device.OpenPorts {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, " ")
}

func padRight(s string, width int) string {
	vis := lipgloss.Width(s)
	if vis >= width {
		// Truncate to fit
		runes := []rune(s)
		if len(runes) > width && width > 1 {
			return string(runes[:width-1]) + "\u2026"
		}
		return s
	}
	return s + strings.Repeat(" ", width-vis)
}

func padCenter(s string, width int) string {
	vis := lipgloss.Width(s)
	if vis >= width {
		return s
	}
	total := width - vis
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func truncate(text string, length int) string {
	if len(text) <= length {
		return text
	}
	if length <= 1 {
		return "\u2026"
	}
	return text[:length-1] + "\u2026"
}
