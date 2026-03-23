package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/cuz/safestay/internal/tui"
)

var version = "dev"

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Printf("safestay %s\n", version)
			os.Exit(0)
		}
		if arg == "--help" || arg == "-h" {
			fmt.Println("SafeStay Scanner — detect hidden cameras on your network")
			fmt.Println()
			fmt.Println("Usage: safestay [options]")
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println("  --version, -v    Print version and exit")
			fmt.Println("  --help, -h       Print this help and exit")
			fmt.Println()
			fmt.Println("Run with sudo for best results (enables ARP scanning).")
			fmt.Println()
			fmt.Println("Keyboard shortcuts:")
			fmt.Println("  s          Scan network")
			fmt.Println("  o          Open selected device in browser")
			fmt.Println("  1-9        Open specific numbered port")
			fmt.Println("  j/k        Navigate device list")
			fmt.Println("  q          Quit")
			os.Exit(0)
		}
	}

	app := tui.NewApp(version)
	p := tea.NewProgram(&app, tea.WithAltScreen())
	app.SetProgram(p)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
