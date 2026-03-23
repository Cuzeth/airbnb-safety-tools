package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Risk level styles
	HighRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("1"))

	MediumRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("3"))

	LowRiskStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("2"))

	UnknownRiskStyle = lipgloss.NewStyle().
				Faint(true)

	// Text colors for risk
	HighRiskText   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	MediumRiskText = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	LowRiskText    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))

	// Header style
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	// Banner style
	BannerStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("252"))

	// Status bar style
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	// Detail panel border
	DetailPanelStyle = lipgloss.NewStyle().
				BorderLeft(true).
				BorderStyle(lipgloss.ThickBorder()).
				BorderForeground(lipgloss.Color("62")).
				Padding(1, 2)

	// Footer/help style
	HelpStyle = lipgloss.NewStyle().
			Faint(true).
			Padding(0, 1)

	// Bold label
	BoldStyle = lipgloss.NewStyle().Bold(true)

	// Dim style
	DimStyle = lipgloss.NewStyle().Faint(true)

	// Cyan style for URLs
	CyanStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	BoldCyanStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))

	// Underline style
	UnderlineStyle = lipgloss.NewStyle().Bold(true).Underline(true)

	// Table styles
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("15")).
				Background(lipgloss.Color("240")).
				Padding(0, 1)

	TableSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("15")).
				Background(lipgloss.Color("62"))

	TableCellStyle = lipgloss.NewStyle().Padding(0, 1)
)
