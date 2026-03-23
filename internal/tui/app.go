package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pkg/browser"

	"github.com/cuz/safestay/internal/fingerprint"
	"github.com/cuz/safestay/internal/model"
	"github.com/cuz/safestay/internal/network"
	"github.com/cuz/safestay/internal/scan"
)

// Fixed chrome heights (lines consumed by non-table UI).
const (
	headerLines = 1
	bannerLines = 1
	statusLines = 1
	helpLines   = 1
	chromeLines = headerLines + bannerLines + statusLines + helpLines
)

// focusPane tracks which panel has keyboard focus.
type focusPane int

const (
	focusTable  focusPane = iota
	focusDetail
)

// AppModel is the top-level Bubble Tea model.
type AppModel struct {
	table        tableModel
	detailVP     viewport.Model
	detailDevice *model.Device
	detailWidth  int
	detailHeight int
	focus        focusPane

	statusBar    string
	banner       string
	subnet       string
	devices      map[string]*model.Device
	scanning     bool
	width        int
	height       int
	version      string
	notification string
	program      *tea.Program
}

// NewApp creates a new AppModel.
func NewApp(version string) AppModel {
	subnet, _ := network.DetectSubnet()
	banner := buildBanner(subnet)

	return AppModel{
		table:     newTableModel(),
		focus:     focusTable,
		statusBar: "Press s to scan  |  Devices: 0",
		banner:    banner,
		subnet:    subnet,
		devices:   make(map[string]*model.Device),
		version:   version,
	}
}

// SetProgram stores the tea.Program reference for p.Send() from goroutines.
func (m *AppModel) SetProgram(p *tea.Program) {
	m.program = p
}

func buildBanner(subnet string) string {
	var parts []string
	if !network.IsRoot() {
		parts = append(parts,
			MediumRiskText.Render("Warning:")+
				" Not running as root. Run with "+BoldStyle.Render("sudo")+" for best results.",
		)
	}
	if subnet != "" {
		parts = append(parts, "Network: "+BoldCyanStyle.Render(subnet))
	} else {
		parts = append(parts, HighRiskText.Render("Could not detect network.")+" Are you connected to WiFi?")
	}
	return strings.Join(parts, "  |  ")
}

func (m *AppModel) Init() tea.Cmd {
	return nil
}

func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalcLayout()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case DevicesDiscoveredMsg:
		m.table.Clear()
		for _, device := range msg.Devices {
			fingerprint.LookupVendor(device)
			m.devices[device.MAC] = device
			m.table.AddDevice(device)
		}
		m.statusBar = fmt.Sprintf("Found %d devices. Port scanning...", len(msg.Devices))
		m.updateDetail()
		m.startPortScans(msg.Devices)
		return m, nil

	case DeviceScanCompleteMsg:
		m.devices[msg.Device.MAC] = msg.Device
		m.table.UpdateDevice(msg.Device)
		m.updateDetail()
		return m, nil

	case ScanStatusMsg:
		m.statusBar = msg.Text
		return m, nil

	case ScanFinishedMsg:
		m.scanning = false
		m.statusBar = fmt.Sprintf(
			"Scan complete  |  Devices: %d  |  %s  |  %s  |  %s",
			msg.Total,
			HighRiskText.Render(fmt.Sprintf("HIGH: %d", msg.High)),
			MediumRiskText.Render(fmt.Sprintf("MEDIUM: %d", msg.Medium)),
			LowRiskText.Render(fmt.Sprintf("LOW: %d", msg.Low)),
		)
		if msg.High > 0 {
			m.notification = HighRiskText.Render(fmt.Sprintf("Found %d HIGH risk device(s)!", msg.High))
		}
		return m, nil

	case ErrorMsg:
		m.scanning = false
		m.statusBar = HighRiskText.Render(fmt.Sprintf("Error: %v", msg.Err))
		return m, nil
	}

	return m, nil
}

func (m *AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global keys (work regardless of focus)
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "s":
		if m.scanning || m.subnet == "" {
			if m.subnet == "" {
				m.statusBar = HighRiskText.Render("No network detected!")
			}
			return m, nil
		}
		m.scanning = true
		m.notification = ""
		m.statusBar = fmt.Sprintf("Discovering devices on %s...", m.subnet)
		return m, m.startDiscovery()
	case "o":
		m.openPort(0)
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0] - '0')
		m.openPort(idx)
		return m, nil
	case "tab":
		// Toggle focus between table and detail
		if m.focus == focusTable {
			m.focus = focusDetail
		} else {
			m.focus = focusTable
		}
		return m, nil
	}

	// Panel-specific keys
	if m.focus == focusTable {
		switch key {
		case "up", "k":
			m.table.MoveUp()
			m.updateDetail()
		case "down", "j":
			m.table.MoveDown()
			m.updateDetail()
		}
	} else {
		// Detail panel focused — scroll it
		switch key {
		case "up", "k":
			m.detailVP.LineUp(1)
		case "down", "j":
			m.detailVP.LineDown(1)
		case "pgup":
			m.detailVP.ViewUp()
		case "pgdown":
			m.detailVP.ViewDown()
		case "home", "g":
			m.detailVP.GotoTop()
		case "end", "G":
			m.detailVP.GotoBottom()
		}
	}

	return m, nil
}

func (m *AppModel) openPort(index int) {
	sel := m.table.SelectedDevice()
	if sel == nil {
		m.notification = "No device selected"
		return
	}
	openable := sel.GetOpenablePorts()
	if len(openable) == 0 {
		m.notification = fmt.Sprintf("No web interface on %s", sel.IP)
		return
	}
	targetIdx := 0
	if index > 0 {
		targetIdx = index - 1
	}
	if targetIdx >= len(openable) {
		m.notification = fmt.Sprintf("No port [%d]", index)
		return
	}
	url := openable[targetIdx].URL
	browser.OpenURL(url)
	m.notification = fmt.Sprintf("Opening %s", url)
}

func (m *AppModel) startDiscovery() tea.Cmd {
	subnet := m.subnet
	return func() tea.Msg {
		devices, err := network.DiscoverDevices(subnet)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		if len(devices) == 0 {
			return ErrorMsg{Err: fmt.Errorf("no devices found — network may use client isolation")}
		}
		return DevicesDiscoveredMsg{Devices: devices}
	}
}

func (m *AppModel) startPortScans(devices []*model.Device) {
	p := m.program
	if p == nil {
		return
	}

	go func() {
		total := len(devices)
		for i, d := range devices {
			p.Send(ScanStatusMsg{
				Text: fmt.Sprintf("Port scanning %d/%d: %s...", i+1, total, d.IP),
			})

			d.OpenPorts = scan.ScanPorts(d.IP, nil)
			fingerprint.FingerprintDevice(d)

			p.Send(DeviceScanCompleteMsg{Device: d})
		}

		high, medium := 0, 0
		for _, d := range devices {
			switch d.RiskLevel {
			case model.RiskHigh:
				high++
			case model.RiskMedium:
				medium++
			}
		}
		p.Send(ScanFinishedMsg{
			Total:  total,
			High:   high,
			Medium: medium,
			Low:    total - high - medium,
		})
	}()
}

func (m *AppModel) updateDetail() {
	sel := m.table.SelectedDevice()
	if sel == nil {
		return
	}
	if m.detailDevice == nil || m.detailDevice.MAC != sel.MAC {
		m.detailDevice = sel
		content := renderDetail(sel, m.detailWidth)
		m.detailVP.SetContent(content)
		m.detailVP.GotoTop()
	} else {
		// Same device, refresh content (ports may have updated)
		content := renderDetail(sel, m.detailWidth)
		m.detailVP.SetContent(content)
	}
}

func (m *AppModel) recalcLayout() {
	mainHeight := m.height - chromeLines
	if mainHeight < 3 {
		mainHeight = 3
	}

	// DetailPanelStyle has: BorderLeft (1 char) + Padding(1, 2) = 1 border + 2 left pad + 2 right pad = 5 extra cols
	// and vertical padding: 1 top + 1 bottom = 2 extra rows
	const detailBorderPad = 5 // horizontal: 1 border + 2+2 padding
	const detailVertPad = 2   // vertical: 1+1 padding

	// Budget for the detail panel's outer width (border + padding + content)
	detailOuter := m.width / 4
	if detailOuter < 32 {
		detailOuter = 32
	}
	if detailOuter > m.width-40 {
		detailOuter = m.width - 40
	}
	if detailOuter < 20 {
		detailOuter = 20
	}

	// Inner content width = outer budget minus border+padding
	m.detailWidth = detailOuter - detailBorderPad
	if m.detailWidth < 15 {
		m.detailWidth = 15
	}
	m.detailHeight = mainHeight

	// Table gets the remaining width
	tableWidth := m.width - detailOuter
	if tableWidth < 40 {
		tableWidth = 40
	}

	// Table height = mainHeight minus 1 for header row
	m.table.SetSize(tableWidth, mainHeight-1)

	// Viewport dimensions = inner content area
	m.detailVP.Width = m.detailWidth
	m.detailVP.Height = mainHeight - detailVertPad
	if m.detailVP.Height < 1 {
		m.detailVP.Height = 1
	}

	if m.detailDevice != nil {
		content := renderDetail(m.detailDevice, m.detailWidth)
		m.detailVP.SetContent(content)
	}
}

func (m *AppModel) View() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}

	// ── Header ──
	header := HeaderStyle.Width(m.width).Render("SafeStay Scanner")

	// ── Banner ──
	bannerText := m.banner
	if m.notification != "" {
		bannerText += "  |  " + m.notification
	}
	bannerLine := BannerStyle.Width(m.width).Render(bannerText)

	// ── Table (left) ──
	tableView := m.table.View()

	// ── Detail (right) ──
	var detailContent string
	if m.detailDevice != nil {
		detailContent = m.detailVP.View()

		// Add scroll indicator if content overflows
		pct := m.detailVP.ScrollPercent()
		if pct < 1.0 && m.detailVP.TotalLineCount() > m.detailVP.Height {
			indicator := DimStyle.Render(fmt.Sprintf(" %.0f%%", pct*100))
			if m.focus == focusDetail {
				indicator = BoldCyanStyle.Render(fmt.Sprintf(" %.0f%%", pct*100))
			}
			detailContent += "\n" + indicator
		}
	} else {
		detailContent = DimStyle.Render("Select a device to view details")
	}

	// Style the detail panel — highlight border when focused.
	// IMPORTANT: lipgloss .Width() sets the CONTENT width. The border and padding
	// are added outside of that. So we pass m.detailWidth (the inner content width)
	// and the total rendered width will be m.detailWidth + 5 (border+padding).
	dpStyle := DetailPanelStyle
	if m.focus == focusDetail {
		dpStyle = dpStyle.BorderForeground(lipgloss.Color("6"))
	}

	detailPanel := dpStyle.
		Width(m.detailWidth).
		Height(m.detailHeight - 2). // content height (padding adds 2)
		Render(detailContent)

	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, tableView, detailPanel)
	mainContent = clampHeight(mainContent, m.height-chromeLines)

	// ── Status bar ──
	status := StatusBarStyle.Width(m.width).Render(m.statusBar)

	// ── Help ──
	var helpText string
	if m.focus == focusDetail {
		helpText = "tab table  |  j/k scroll  |  g/G top/bottom  |  s scan  |  q quit"
	} else {
		helpText = "s scan  |  o open  |  1-9 port  |  j/k navigate  |  tab details  |  q quit"
	}
	help := HelpStyle.Width(m.width).Render(helpText)

	return header + "\n" + bannerLine + "\n" + mainContent + "\n" + status + "\n" + help
}

func clampHeight(s string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n")
}
