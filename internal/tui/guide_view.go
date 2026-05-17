package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"abdeen.dev/safestay/internal/guide"
)

// renderGuide formats the safety guide as a single scrollable string for the
// help overlay. Width matters because the viewport hard-wraps; we wrap
// paragraphs ourselves so styled bullet markers don't get cut mid-token.
func renderGuide(width int) string {
	if width < 20 {
		width = 20
	}

	var b strings.Builder

	writeGuideHeading(&b, "Physical Check")
	b.WriteString(DimStyle.Render(wrapPlain(
		"Network scanning misses anything on a guest VLAN, on a 4G SIM, or that "+
			"only writes to an SD card. Run this physical sweep too — it takes "+
			"60 seconds and catches a different threat model.", width)))
	b.WriteString("\n\n")
	writeSections(&b, guide.PhysicalCheck, width)

	b.WriteString("\n")
	writeGuideHeading(&b, "What This Tool Cannot See")
	for _, line := range guide.Limits {
		writeBullet(&b, line, width, &DimStyle)
	}

	b.WriteString("\n")
	writeGuideHeading(&b, "Notice")
	for _, line := range guide.LegalNotice {
		writeBullet(&b, line, width, &DimStyle)
	}

	b.WriteString("\n")
	b.WriteString(DimStyle.Render("Press ? or Esc to close."))
	b.WriteString("\n")

	return b.String()
}

// renderGuideBanner returns a one-line teaser shown next to a HIGH result.
func renderGuideBanner(highCount int) string {
	if highCount <= 0 {
		return ""
	}
	plural := ""
	if highCount > 1 {
		plural = "s"
	}
	return HighRiskText.Render(fmt.Sprintf(
		"%d HIGH risk device%s detected.", highCount, plural,
	)) + " " + BoldCyanStyle.Render("Press ?") + DimStyle.Render(" for the physical-check guide")
}

// renderIsolationBanner returns a one-line warning when the scan is unreliable.
func renderIsolationBanner(width int) string {
	msg := "This network appears to use AP / client isolation. " +
		"A network scan cannot reliably find cameras here — run the physical check (press ?)."
	return MediumRiskText.Render("Warning:") + " " + truncateWidth(msg, width-10)
}

func writeGuideHeading(b *strings.Builder, title string) {
	b.WriteString(UnderlineStyle.Render(strings.ToUpper(title)))
	b.WriteString("\n\n")
}

func writeSections(b *strings.Builder, sections []guide.Section, width int) {
	for _, section := range sections {
		b.WriteString(BoldStyle.Render(section.Title))
		b.WriteString("\n")
		for _, item := range section.Items {
			writeBullet(b, item, width, nil)
		}
		b.WriteString("\n")
	}
}

func writeBullet(b *strings.Builder, item string, width int, style *lipgloss.Style) {
	lines := wrapTextLines(item, width-4)
	for i, line := range lines {
		if i == 0 {
			b.WriteString("  • ")
		} else {
			b.WriteString("    ")
		}
		if style != nil {
			b.WriteString(style.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
}

func wrapPlain(text string, width int) string {
	lines := wrapTextLines(text, width)
	return strings.Join(lines, "\n")
}
