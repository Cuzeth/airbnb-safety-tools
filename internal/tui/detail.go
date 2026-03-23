package tui

import (
	"fmt"
	"strings"

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
				for _, line := range wordWrapLines(portInfo.Description, width-4) {
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
			b.WriteString(fmt.Sprintf("  %s %s\n",
				BoldCyanStyle.Render(fmt.Sprintf("[%d]", i+1)),
				CyanStyle.Render(pu.URL),
			))
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
			lines := wordWrapLines(reason, width-4)
			for j, line := range lines {
				if j == 0 {
					b.WriteString(riskReasonStyled("  \u2022 "+line+"\n", device.RiskLevel))
				} else {
					b.WriteString(riskReasonStyled("    "+line+"\n", device.RiskLevel))
				}
			}
		}
	}

	if !device.ScanComplete {
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("Port scan in progress..."))
	}

	return b.String()
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

// wordWrapLines splits text into lines that fit within width.
func wordWrapLines(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	current := words[0]

	for _, word := range words[1:] {
		if len(current)+1+len(word) <= width {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	lines = append(lines, current)
	return lines
}
