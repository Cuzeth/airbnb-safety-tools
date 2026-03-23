package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/cuz/safestay/internal/model"
)

// renderDetail builds the detail panel content as a plain string.
// Styling is applied inline via Lip Gloss. The viewport handles scrolling.
func renderDetail(device *model.Device, width int) string {
	if width < 10 {
		width = 10
	}

	var b strings.Builder

	b.WriteString(UnderlineStyle.Render("DEVICE DETAILS"))
	b.WriteString("\n\n")

	writeField(&b, "IP:       ", device.IP)
	writeField(&b, "MAC:      ", device.MAC)
	writeField(&b, "Vendor:   ", device.Vendor)
	writeField(&b, "Category: ", string(device.Category))
	b.WriteString("\n")
	b.WriteString(BoldStyle.Render("Risk:     "))
	b.WriteString(riskStyled(device.RiskLevel))
	b.WriteString("\n")

	// Open ports with detailed descriptions
	if len(device.OpenPorts) > 0 {
		b.WriteString("\n")
		b.WriteString(UnderlineStyle.Render("Open Ports:"))
		b.WriteString("\n")
		for _, port := range device.OpenPorts {
			portInfo, ok := model.PortDatabase[port]
			if ok {
				portStr := fmt.Sprintf("%d", port)
				proto := fmt.Sprintf("/%s", portInfo.Protocol)
				b.WriteString("  ")
				b.WriteString(BoldStyle.Render(portStr))
				b.WriteString(portRiskStyled(proto, portInfo.Risk))
				b.WriteString("\n")
				for _, line := range wrapTextLines(portInfo.Description, width-4) {
					b.WriteString("    ")
					b.WriteString(DimStyle.Render(line))
					b.WriteString("\n")
				}
			} else {
				b.WriteString(fmt.Sprintf("  %s\n", BoldStyle.Render(fmt.Sprintf("%d", port))))
			}
		}
	}

	// Numbered browser-openable ports
	openable := device.GetOpenablePorts()
	if len(openable) > 0 {
		b.WriteString("\n")
		b.WriteString(UnderlineStyle.Render("Open in Browser:"))
		b.WriteString("\n")
		limit := len(openable)
		if limit > 9 {
			limit = 9
		}
		for i := 0; i < limit; i++ {
			pu := openable[i]
			label := fmt.Sprintf("[%d]", i+1)
			wrapped := wrapTextLines(pu.URL, width-6)
			for lineIndex, line := range wrapped {
				if lineIndex == 0 {
					b.WriteString("  ")
					b.WriteString(BoldCyanStyle.Render(label))
					b.WriteString(" ")
				} else {
					b.WriteString("     ")
				}
				b.WriteString(CyanStyle.Render(line))
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("Press "))
		b.WriteString(BoldCyanStyle.Render("1"))
		if limit > 1 {
			b.WriteString(BoldCyanStyle.Render(fmt.Sprintf("-%d", limit)))
		}
		b.WriteString(DimStyle.Render(" to open  "))
		b.WriteString(BoldCyanStyle.Render("o"))
		b.WriteString(DimStyle.Render(" opens first"))
		b.WriteString("\n")
	}

	// Risk analysis reasons
	if len(device.RiskReasons) > 0 {
		b.WriteString("\n")
		b.WriteString(UnderlineStyle.Render("Risk Analysis:"))
		b.WriteString("\n")
		for _, reason := range device.RiskReasons {
			lines := wrapTextLines(reason, width-4)
			for j, line := range lines {
				if j == 0 {
					b.WriteString(riskReasonStyled("  \u2022 "+line, device.RiskLevel))
				} else {
					b.WriteString(riskReasonStyled("    "+line, device.RiskLevel))
				}
				b.WriteString("\n")
			}
		}
	}

	if !device.ScanComplete {
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("Port scan in progress..."))
	}

	return b.String()
}

func renderDetailPlaceholder(width int, title, body string) string {
	if width < 10 {
		width = 10
	}
	if title == "" {
		title = "DEVICE DETAILS"
	}
	if body == "" {
		body = "Select a device to view details."
	}

	var b strings.Builder
	b.WriteString(UnderlineStyle.Render(title))
	b.WriteString("\n\n")
	for _, line := range wrapTextLines(body, width) {
		b.WriteString(DimStyle.Render(line))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeField(b *strings.Builder, label, value string) {
	b.WriteString(BoldStyle.Render(label))
	b.WriteString(value)
	b.WriteString("\n")
}

func riskStyled(risk model.RiskLevel) string {
	switch risk {
	case model.RiskHigh:
		return HighRiskStyle.Render("  HIGH  ")
	case model.RiskMedium:
		return MediumRiskStyle.Render(" MEDIUM ")
	case model.RiskLow:
		return LowRiskStyle.Render("  LOW   ")
	default:
		return UnknownRiskStyle.Render("   ?    ")
	}
}

func portRiskStyled(text string, risk model.RiskLevel) string {
	switch risk {
	case model.RiskHigh:
		return HighRiskText.Render(text)
	case model.RiskMedium:
		return MediumRiskText.Render(text)
	default:
		return text
	}
}

func riskReasonStyled(text string, risk model.RiskLevel) string {
	switch risk {
	case model.RiskHigh:
		return HighRiskText.Render(text)
	case model.RiskMedium:
		return MediumRiskText.Render(text)
	case model.RiskLow:
		return LowRiskText.Render(text)
	default:
		return DimStyle.Render(text)
	}
}

// wrapTextLines splits text into lines that fit within width using display width
// instead of raw byte length, and it hard-wraps long tokens when needed.
func wrapTextLines(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}

	paragraphs := strings.Split(text, "\n")
	var lines []string
	for _, paragraph := range paragraphs {
		wrapped := wrapParagraph(paragraph, width)
		lines = append(lines, wrapped...)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func wrapParagraph(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	current := ""

	for _, word := range words {
		for visibleWidth(word) > width {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			chunk, rest := splitByWidth(word, width)
			lines = append(lines, chunk)
			word = rest
		}

		if current == "" {
			current = word
			continue
		}

		candidate := current + " " + word
		if visibleWidth(candidate) <= width {
			current = candidate
			continue
		}

		lines = append(lines, current)
		current = word
	}

	if current != "" {
		lines = append(lines, current)
	}

	return lines
}

func splitByWidth(text string, width int) (string, string) {
	if width <= 0 {
		return "", text
	}

	var b strings.Builder
	for i, r := range text {
		next := b.String() + string(r)
		if visibleWidth(next) > width {
			if b.Len() == 0 {
				return string(r), text[i+len(string(r)):]
			}
			return b.String(), text[i:]
		}
		b.WriteRune(r)
	}

	return b.String(), ""
}

func visibleWidth(text string) int {
	return lipgloss.Width(text)
}
