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
	focusTable focusPane = iota
	focusDetail
)

// AppModel is the top-level Bubble Tea model.
type AppModel struct {
	table        tableModel
	detailVP     viewport.Model
	detailDevice *model.Device
	detailPaneW  int
	detailWidth  int
	detailHeight int
	compact      bool
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
	emptyMessage string
	statusCounts *scanCounts
	program      *tea.Program
}

type scanCounts struct {
	Total  int
	High   int
	Medium int
	Low    int
}

// NewApp creates a new AppModel.
func NewApp(version string) AppModel {
	subnet, _ := network.DetectSubnet()
	banner := buildBanner(subnet)

	return AppModel{
		table:        newTableModel(),
		focus:        focusTable,
		statusBar:    "Press s to scan  |  Devices: 0",
		banner:       banner,
		subnet:       subnet,
		devices:      make(map[string]*model.Device),
		version:      version,
		emptyMessage: "Press s to scan the local network",
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
		m.devices = make(map[string]*model.Device, len(msg.Devices))
		m.emptyMessage = ""
		for _, device := range msg.Devices {
			fingerprint.LookupVendor(device)
			m.devices[device.MAC] = device
			m.table.AddDevice(device)
		}
		m.statusBar = fmt.Sprintf("Found %d devices. Port scanning...", len(msg.Devices))
		m.statusCounts = nil
		m.updateDetail()
		m.startPortScans(msg.Devices)
		return m, nil

	case NoDevicesMsg:
		m.scanning = false
		m.resetResults()
		m.emptyMessage = msg.Reason
		m.statusBar = "No devices found. The network may use client isolation."
		m.statusCounts = nil
		m.notification = msg.Reason
		return m, nil

	case DeviceScanCompleteMsg:
		m.devices[msg.Device.MAC] = msg.Device
		m.table.UpdateDevice(msg.Device)
		m.updateDetail()
		return m, nil

	case ScanStatusMsg:
		m.statusBar = msg.Text
		m.statusCounts = nil
		return m, nil

	case ScanFinishedMsg:
		m.scanning = false
		m.statusBar = fmt.Sprintf(
			"Scan complete  |  Devices: %d  |  HIGH: %d  |  MEDIUM: %d  |  LOW: %d",
			msg.Total,
			msg.High,
			msg.Medium,
			msg.Low,
		)
		m.statusCounts = &scanCounts{
			Total:  msg.Total,
			High:   msg.High,
			Medium: msg.Medium,
			Low:    msg.Low,
		}
		if msg.High > 0 {
			m.notification = HighRiskText.Render(fmt.Sprintf("Found %d HIGH risk device(s)!", msg.High))
		}
		return m, nil

	case ErrorMsg:
		m.scanning = false
		m.resetResults()
		m.emptyMessage = fmt.Sprintf("Scan failed: %v", msg.Err)
		m.statusBar = fmt.Sprintf("Error: %v", msg.Err)
		m.statusCounts = nil
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
				m.statusBar = "No network detected!"
			}
			return m, nil
		}
		return m, m.beginScan()
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
		case "pgup":
			m.table.MovePageUp()
			m.updateDetail()
		case "pgdown":
			m.table.MovePageDown()
			m.updateDetail()
		case "home", "g":
			m.table.MoveTop()
			m.updateDetail()
		case "end", "G":
			m.table.MoveBottom()
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

func (m *AppModel) beginScan() tea.Cmd {
	m.scanning = true
	m.notification = ""
	m.emptyMessage = fmt.Sprintf("Discovering devices on %s...", m.subnet)
	m.statusBar = fmt.Sprintf("Discovering devices on %s...", m.subnet)
	m.statusCounts = nil
	m.resetResults()
	return m.startDiscovery()
}

func (m *AppModel) resetResults() {
	m.table.Clear()
	m.devices = make(map[string]*model.Device)
	m.detailDevice = nil
	m.detailVP.SetContent("")
	m.detailVP.GotoTop()
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
		m.notification = fmt.Sprintf("No port [%d] on %s", index, sel.IP)
		return
	}
	url := openable[targetIdx].URL
	if err := browser.OpenURL(url); err != nil {
		m.notification = fmt.Sprintf("Could not open %s: %v", url, err)
		return
	}
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
			return NoDevicesMsg{Reason: "No devices found. The network may use AP isolation or client isolation."}
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
		high, medium := 0, 0
		for i, d := range devices {
			p.Send(ScanStatusMsg{
				Text: fmt.Sprintf("Port scanning %d/%d: %s...", i+1, total, d.IP),
			})

			scanned := d.Clone()
			scanned.OpenPorts = scan.ScanPorts(scanned.IP, nil)
			fingerprint.FingerprintDevice(scanned)
			switch scanned.RiskLevel {
			case model.RiskHigh:
				high++
			case model.RiskMedium:
				medium++
			}

			p.Send(DeviceScanCompleteMsg{Device: scanned})
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
		m.detailDevice = nil
		m.detailVP.SetContent("")
		m.detailVP.GotoTop()
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

	detailFrameW := DetailPanelStyle.GetHorizontalFrameSize()
	detailFrameH := DetailPanelStyle.GetVerticalFrameSize()
	const minTableWidth = 52
	const minDetailWidth = 34

	m.compact = m.width < (minTableWidth + minDetailWidth)
	if m.compact {
		m.detailPaneW = m.width
		m.table.SetSize(m.width, mainHeight-1)
	} else {
		detailOuter := clampInt(m.width/3, minDetailWidth, m.width-minTableWidth)
		m.detailPaneW = detailOuter
		m.table.SetSize(m.width-detailOuter, mainHeight-1)
	}

	m.detailWidth = m.detailPaneW - detailFrameW
	if m.detailWidth < 15 {
		m.detailWidth = 15
	}
	m.detailHeight = mainHeight

	// Viewport dimensions = inner content area
	m.detailVP.Width = m.detailWidth
	m.detailVP.Height = mainHeight - detailFrameH
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
	header := renderSizedLine(HeaderStyle, m.width, "SafeStay Scanner")

	// ── Banner ──
	bannerText := m.banner
	if m.notification != "" {
		bannerText += "  |  " + m.notification
	}
	bannerLine := renderSizedLine(BannerStyle, m.width, truncateWidth(bannerText, m.width-BannerStyle.GetHorizontalFrameSize()))

	// ── Table (left) ──
	tableView := m.table.View(m.emptyMessage)

	// ── Detail (right) ──
	var detailContent string
	if m.detailDevice != nil {
		detailContent = m.detailVP.View()
	} else {
		title := "DEVICE DETAILS"
		body := m.emptyMessage
		if body == "" {
			body = "Select a device to view details."
		}
		detailContent = renderDetailPlaceholder(m.detailWidth, title, body)
	}

	// Style the detail panel — highlight border when focused.
	dpStyle := DetailPanelStyle
	if m.focus == focusDetail {
		dpStyle = dpStyle.BorderForeground(sky400)
	}

	detailPanel := renderSizedBlock(dpStyle, m.detailPaneW, m.detailHeight, detailContent)

	mainContent := tableView
	if m.compact {
		if m.focus == focusDetail {
			mainContent = detailPanel
		}
	} else {
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, tableView, detailPanel)
	}
	mainContent = clampHeight(mainContent, m.height-chromeLines)

	// ── Status bar ──
	status := m.renderStatusBar()

	// ── Help ──
	var helpText string
	if m.focus == focusDetail {
		helpText = "tab table  |  j/k scroll  |  pgup/pgdn page  |  g/G top/bottom  |  s scan  |  q quit"
	} else {
		helpText = "s scan  |  o open  |  1-9 port  |  j/k navigate  |  pgup/pgdn page  |  tab details  |  q quit"
	}
	help := renderSizedLine(HelpStyle, m.width, truncateWidth(helpText, m.width-HelpStyle.GetHorizontalFrameSize()))

	return header + "\n" + bannerLine + "\n" + mainContent + "\n" + status + "\n" + help
}

func (m *AppModel) renderStatusBar() string {
	if m.statusCounts == nil {
		return renderSizedLine(StatusBarStyle, m.width, truncateWidth(m.statusBar, m.width-StatusBarStyle.GetHorizontalFrameSize()))
	}

	plain := fmt.Sprintf(
		" Scan complete  |  Devices: %d  |  HIGH: %d  |  MEDIUM: %d  |  LOW: %d ",
		m.statusCounts.Total,
		m.statusCounts.High,
		m.statusCounts.Medium,
		m.statusCounts.Low,
	)
	if visibleWidth(plain) > m.width {
		return renderSizedLine(StatusBarStyle, m.width, truncateWidth(plain, m.width-StatusBarStyle.GetHorizontalFrameSize()))
	}

	line := strings.Join([]string{
		StatusBarBaseStyle.Render(" Scan complete  |  Devices: "),
		StatusBarBaseStyle.Render(fmt.Sprintf("%d", m.statusCounts.Total)),
		StatusBarBaseStyle.Render("  |  "),
		StatusBarHighText.Render(fmt.Sprintf("HIGH: %d", m.statusCounts.High)),
		StatusBarBaseStyle.Render("  |  "),
		StatusBarMediumText.Render(fmt.Sprintf("MEDIUM: %d", m.statusCounts.Medium)),
		StatusBarBaseStyle.Render("  |  "),
		StatusBarLowText.Render(fmt.Sprintf("LOW: %d", m.statusCounts.Low)),
		StatusBarBaseStyle.Render(" "),
	}, "")

	if padding := m.width - visibleWidth(line); padding > 0 {
		line += StatusBarBaseStyle.Render(strings.Repeat(" ", padding))
	}

	return line
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
