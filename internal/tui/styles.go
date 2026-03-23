package tui

import "github.com/charmbracelet/lipgloss"

// ── Palette ─────────────────────────────────────────────────────────
// Slate family for chrome, sky-blue accent, Tailwind-inspired risk colors.
var (
	slate50  = lipgloss.Color("#F8FAFC")
	slate400 = lipgloss.Color("#94A3B8")
	slate500 = lipgloss.Color("#64748B")
	slate600 = lipgloss.Color("#475569")
	slate700 = lipgloss.Color("#334155")
	sky400   = lipgloss.Color("#38BDF8")
	deepBlue = lipgloss.Color("#1E3A5F")
)

var (
	// Risk level badge styles (colored background)
	HighRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FEF2F2")).
			Background(lipgloss.Color("#991B1B"))

	MediumRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#1C1917")).
			Background(lipgloss.Color("#D97706"))

	LowRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F0FDF4")).
			Background(lipgloss.Color("#166534"))

	UnknownRiskStyle = lipgloss.NewStyle().
				Faint(true)

	// Text colors for risk (inline, no background)
	HighRiskText   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F87171"))
	MediumRiskText = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FBBF24"))
	LowRiskText    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4ADE80"))

	// Header style
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(slate50).
			Background(slate700).
			Padding(0, 1)

	// Banner style
	BannerStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(slate400)

	// Status bar styles
	StatusBarBaseStyle = lipgloss.NewStyle().
				Foreground(slate50).
				Background(slate700)

	StatusBarStyle = StatusBarBaseStyle.
			Padding(0, 1)

	StatusBarHighText = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#F87171")).
				Background(slate700)

	StatusBarMediumText = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FBBF24")).
				Background(slate700)

	StatusBarLowText = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#4ADE80")).
				Background(slate700)

	// Detail panel border
	DetailPanelStyle = lipgloss.NewStyle().
				BorderLeft(true).
				BorderStyle(lipgloss.ThickBorder()).
				BorderForeground(slate500).
				Padding(1, 2)

	// Footer/help style
	HelpStyle = lipgloss.NewStyle().
			Faint(true).
			Padding(0, 1)

	// Bold label
	BoldStyle = lipgloss.NewStyle().Bold(true)

	// Dim style
	DimStyle = lipgloss.NewStyle().Faint(true)

	// Accent style for URLs and interactive elements
	CyanStyle     = lipgloss.NewStyle().Foreground(sky400)
	BoldCyanStyle = lipgloss.NewStyle().Bold(true).Foreground(sky400)

	// Underline style
	UnderlineStyle = lipgloss.NewStyle().Bold(true).Underline(true)

	// Table styles
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(slate50).
				Background(slate600)

	TableSelectedStyle = lipgloss.NewStyle().
				Foreground(slate50).
				Background(deepBlue)

	TableCellStyle = lipgloss.NewStyle().Padding(0, 1)
)
