package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestTableViewRendersFixedSizeEmptyState(t *testing.T) {
	table := newTableModel()
	table.SetSize(80, 5)

	view := table.View("Discovering devices on 192.168.1.0/24...")
	lines := strings.Split(view, "\n")

	if got, want := len(lines), 6; got != want {
		t.Fatalf("unexpected line count: got %d want %d", got, want)
	}

	for i, line := range lines {
		if got, want := lipgloss.Width(line), 80; got != want {
			t.Fatalf("line %d width mismatch: got %d want %d", i, got, want)
		}
	}

	if !strings.Contains(view, "Discovering devices") {
		t.Fatalf("expected placeholder message in view, got %q", view)
	}
}
