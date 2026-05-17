package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"abdeen.dev/safestay/internal/tui"
)

var version = "dev"

const shortDisclaimer = `SafeStay — MIT-licensed, AS IS, no warranty, no liability. Not legal advice.
Network scanning may be illegal where you are — that's on you to check before
running it. If unsure, don't run it.`

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version", "-v":
			fmt.Printf("safestay %s\n", version)
			os.Exit(0)
		case "--help", "-h":
			printHelp()
			os.Exit(0)
		}
	}

	fmt.Fprintln(os.Stderr, shortDisclaimer)
	fmt.Fprintln(os.Stderr)

	app := tui.NewApp(version)
	p := tea.NewProgram(&app, tea.WithAltScreen())
	app.SetProgram(p)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("SafeStay Scanner — detect hidden cameras on your network")
	fmt.Println()
	fmt.Println("Usage: safestay [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --version, -v    Print version and exit")
	fmt.Println("  --help, -h       Print this help and exit")
	fmt.Println()
	fmt.Println("Run with sudo for best results (lets the discovery phase send")
	fmt.Println("raw ICMP probes, putting more devices in the ARP cache).")
	fmt.Println()
	fmt.Println("Keyboard shortcuts:")
	fmt.Println("  s          Scan network")
	fmt.Println("  e          Export report (HTML + JSON)")
	fmt.Println("  o          Open selected device in browser")
	fmt.Println("  1-9        Open specific numbered port")
	fmt.Println("  ?          Physical-check guide")
	fmt.Println("  esc        Close the guide")
	fmt.Println("  j/k        Move within focused pane")
	fmt.Println("  pgup/pgdn  Page through table or detail panel")
	fmt.Println("  g/G        Jump to top/bottom")
	fmt.Println("  tab        Toggle table/detail focus")
	fmt.Println("  q          Quit")
	fmt.Println()
	fmt.Println("MIT-licensed. AS IS, no warranty, no liability. Not legal advice.")
}
