package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pkg/browser"

	"abdeen.dev/safestay/internal/fingerprint"
	"abdeen.dev/safestay/internal/model"
	"abdeen.dev/safestay/internal/network"
	"abdeen.dev/safestay/internal/report"
	"abdeen.dev/safestay/internal/scan"
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

// viewMode toggles between the normal scan layout and the safety-guide overlay.
type viewMode int

const (
	modeNormal viewMode = iota
	modeGuide
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

	mode      viewMode
	guideVP   viewport.Model
	guideText string

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
	reliability  model.ScanReliability
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
		mode:         modeNormal,
		statusBar:    "Press s to scan  |  ? for help",
		banner:       banner,
		subnet:       subnet,
		devices:      make(map[string]*model.Device),
		version:      version,
		reliability:  model.ReliabilityNormal,
		emptyMessage: "Press s to scan the local network. Press ? for the physical-check guide.",
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
		m.reliability = msg.Reliability
		m.statusBar = fmt.Sprintf("Found %d devices. Port scanning...", len(msg.Devices))
		m.statusCounts = nil
		if msg.Reliability == model.ReliabilityIsolated {
			m.notification = "Network appears isolated. Press ? for the physical-check guide."
		} else if msg.Reliability == model.ReliabilityPartial {
			m.notification = "Few devices found — results may be incomplete. Press ? for the physical-check guide."
		}
		m.updateDetail()
		m.startPortScans(msg.Devices)
		return m, nil

	case NoDevicesMsg:
		m.scanning = false
		m.resetResults()
		m.reliability = model.ReliabilityIsolated
		m.emptyMessage = msg.Reason
		m.statusBar = "No devices found. Network may use AP isolation. Press ? for the physical check."
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
			m.notification = renderGuideBanner(msg.High)
		} else if m.reliability == model.ReliabilityNormal {
			m.notification = "No high-risk devices detected — but always pair this with a physical sweep (press ?)."
		}
		return m, nil

	case ErrorMsg:
		m.scanning = false
		m.resetResults()
		m.emptyMessage = fmt.Sprintf("Scan failed: %v", msg.Err)
		m.statusBar = fmt.Sprintf("Error: %v", msg.Err)
		m.statusCounts = nil
		return m, nil

	case ReportSavedMsg:
		m.notification = fmt.Sprintf("Report saved: %s", msg.Path)
		return m, nil

	case ReportErrorMsg:
		m.notification = fmt.Sprintf("Export failed: %v", msg.Err)
		return m, nil
	}

	return m, nil
}

func (m *AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Guide overlay swallows most keys.
	if m.mode == modeGuide {
		switch key {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?", "esc":
			m.mode = modeNormal
			return m, nil
		case "up", "k":
			m.guideVP.LineUp(1)
		case "down", "j":
			m.guideVP.LineDown(1)
		case "pgup":
			m.guideVP.ViewUp()
		case "pgdown", " ":
			m.guideVP.ViewDown()
		case "home", "g":
			m.guideVP.GotoTop()
		case "end", "G":
			m.guideVP.GotoBottom()
		}
		return m, nil
	}

	// Global keys (work regardless of focus)
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.openGuide()
		return m, nil
	case "s":
		if m.scanning || m.subnet == "" {
			if m.subnet == "" {
				m.statusBar = "No network detected!"
			}
			return m, nil
		}
		return m, m.beginScan()
	case "e":
		if len(m.devices) == 0 {
			m.notification = "No scan results to export"
			return m, nil
		}
		if m.scanning {
			m.notification = "Wait for scan to complete"
			return m, nil
		}
		return m, m.exportReport()
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

func (m *AppModel) exportReport() tea.Cmd {
	devices := make([]*model.Device, 0, len(m.devices))
	for _, d := range m.devices {
		devices = append(devices, d)
	}
	subnet := m.subnet
	version := m.version
	reliability := m.reliability

	return func() tea.Msg {
		path, err := report.GenerateWithReliability(devices, subnet, version, reliability)
		if err != nil {
			return ReportErrorMsg{Err: err}
		}
		return ReportSavedMsg{Path: path}
	}
}

func (m *AppModel) startDiscovery() tea.Cmd {
	subnet := m.subnet
	return func() tea.Msg {
		result, err := network.DiscoverDevices(subnet)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		if len(result.Devices) == 0 {
			return NoDevicesMsg{Reason: "No devices found. The network may use AP isolation or client isolation — press ? for the physical-check guide."}
		}
		return DevicesDiscoveredMsg{
			Devices:     result.Devices,
			Reliability: result.Reliability,
			GatewayIP:   result.GatewayIP,
			LocalIP:     result.LocalIP,
		}
	}
}

func (m *AppModel) openGuide() {
	m.mode = modeGuide
	m.recalcLayout()
	m.guideText = renderGuide(m.guideVP.Width)
	m.guideVP.SetContent(m.guideText)
	m.guideVP.GotoTop()
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

	// Guide overlay uses full inner width.
	guideWidth := m.width - DetailPanelStyle.GetHorizontalFrameSize()
	if guideWidth < 20 {
		guideWidth = 20
	}
	m.guideVP.Width = guideWidth
	m.guideVP.Height = mainHeight - detailFrameH
	if m.guideVP.Height < 1 {
		m.guideVP.Height = 1
	}
	if m.mode == modeGuide {
		m.guideText = renderGuide(guideWidth)
		m.guideVP.SetContent(m.guideText)
	}
}

func (m *AppModel) View() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}

	header := renderSizedLine(HeaderStyle, m.width, "SafeStay Scanner")

	bannerText := m.bannerText()
	bannerLine := renderSizedLine(BannerStyle, m.width, truncateWidth(bannerText, m.width-BannerStyle.GetHorizontalFrameSize()))

	mainContent := m.renderMain()
	mainContent = clampHeight(mainContent, m.height-chromeLines)

	status := m.renderStatusBar()

	help := renderSizedLine(HelpStyle, m.width, truncateWidth(m.helpText(), m.width-HelpStyle.GetHorizontalFrameSize()))

	return header + "\n" + bannerLine + "\n" + mainContent + "\n" + status + "\n" + help
}

// bannerText composes the top banner, prepending an isolation warning when
// the most recent scan was unreliable.
func (m *AppModel) bannerText() string {
	parts := []string{m.banner}
	if m.reliability == model.ReliabilityIsolated || m.reliability == model.ReliabilityPartial {
		parts = append(parts, renderIsolationBanner(m.width))
	}
	if m.notification != "" {
		parts = append(parts, m.notification)
	}
	return strings.Join(parts, "  |  ")
}

func (m *AppModel) renderMain() string {
	if m.mode == modeGuide {
		return renderSizedBlock(DetailPanelStyle.BorderForeground(sky400), m.width, m.height-chromeLines, m.guideVP.View())
	}

	tableView := m.table.View(m.emptyMessage)

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

	dpStyle := DetailPanelStyle
	if m.focus == focusDetail {
		dpStyle = dpStyle.BorderForeground(sky400)
	}
	detailPanel := renderSizedBlock(dpStyle, m.detailPaneW, m.detailHeight, detailContent)

	if m.compact {
		if m.focus == focusDetail {
			return detailPanel
		}
		return tableView
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, tableView, detailPanel)
}

func (m *AppModel) helpText() string {
	switch {
	case m.mode == modeGuide:
		return "j/k scroll  |  pgup/pgdn page  |  g/G top/bottom  |  ? or esc close  |  q quit"
	case m.focus == focusDetail:
		return "tab table  |  j/k scroll  |  pgup/pgdn page  |  g/G top/bottom  |  s scan  |  ? help  |  q quit"
	default:
		return "s scan  |  e export  |  o open  |  1-9 port  |  j/k navigate  |  tab details  |  ? help  |  q quit"
	}
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
