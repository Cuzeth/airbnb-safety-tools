package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func renderSizedLine(style lipgloss.Style, width int, content string) string {
	if width <= 0 {
		return ""
	}
	return style.Width(width).MaxWidth(width).Render(content)
}

func renderSizedBlock(style lipgloss.Style, width, height int, content string) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	return style.
		Width(width).
		Height(height).
		MaxWidth(width).
		MaxHeight(height).
		Render(content)
}

func truncateWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}

	var b strings.Builder
	for _, r := range s {
		next := b.String() + string(r)
		if lipgloss.Width(next)+1 > width {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "…"
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
