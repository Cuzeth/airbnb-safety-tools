package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"abdeen.dev/safestay/internal/tui"
)

var version = "dev"

// shortDisclaimer is shown above --help and on stderr at startup. It is
// intentionally short so people read it. The full text lives in DISCLAIMER.md
// and is printed by `safestay --disclaimer`.
const shortDisclaimer = `SafeStay is provided "AS IS", with NO WARRANTY and NO LIABILITY.
It is NOT legal advice. The author does NOT condone, encourage, or recommend
its use against any network, device, host, or person. Network scanning may be
illegal in your jurisdiction — you alone are responsible for confirming you
have authorization to scan. By using this software you accept all risk and
agree to the full DISCLAIMER.md and LICENSE files. If unsure, do not run it.`

const fullDisclaimer = `SAFESTAY — LEGAL NOTICE & DISCLAIMER

This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or
implied. The author and contributors:

  - Disclaim all liability for any damages, losses, criminal charges, civil
    claims, account termination, or other consequences of any kind arising
    from the use of this software.
  - Do NOT condone, encourage, endorse, or recommend the use of this tool
    against any network, system, device, or person.
  - Provide NO legal advice. Nothing in this software, its documentation, or
    its output is legal advice. Always consult a licensed attorney in your
    jurisdiction.
  - Make NO claim of accuracy. False positives and false negatives are
    expected — never rely on this tool as the sole basis for any decision
    about your safety.

Network scanning, port scanning, and the techniques used by this tool may be
illegal, regulated, or restricted under your local laws and the terms of
service of the network you are connected to. You alone are responsible for
confirming you have lawful authorization to scan, before you scan.

SafeStay is not affiliated with, endorsed by, or connected to Airbnb, Vrbo,
any hotel chain, or any camera or chip manufacturer named anywhere in this
software. Vendor names appear only as technical references.

If in doubt, do not run this software. If you believe a crime has occurred,
contact local law enforcement and a licensed attorney — not this tool.

For the full disclaimer, see: https://github.com/Cuzeth/airbnb-safety-tools/blob/main/DISCLAIMER.md
`

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version", "-v":
			fmt.Printf("safestay %s\n", version)
			os.Exit(0)
		case "--disclaimer":
			fmt.Print(fullDisclaimer)
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
	fmt.Println("  --disclaimer     Print the full legal disclaimer and exit")
	fmt.Println()
	fmt.Println("Run with sudo for best results (enables ARP scanning).")
	fmt.Println()
	fmt.Println("Keyboard shortcuts:")
	fmt.Println("  s          Scan network")
	fmt.Println("  e          Export report (HTML + JSON)")
	fmt.Println("  o          Open selected device in browser")
	fmt.Println("  1-9        Open specific numbered port")
	fmt.Println("  ?          Safety guide (physical check + what to do)")
	fmt.Println("  esc        Close the safety guide")
	fmt.Println("  j/k        Move within focused pane")
	fmt.Println("  pgup/pgdn  Page through table or detail panel")
	fmt.Println("  g/G        Jump to top/bottom")
	fmt.Println("  tab        Toggle table/detail focus")
	fmt.Println("  q          Quit")
	fmt.Println()
	fmt.Println("LEGAL: Use at your own risk. AS IS, NO WARRANTY, NO LIABILITY.")
	fmt.Println("This tool is NOT legal advice. The author does NOT condone or")
	fmt.Println("recommend its use. Run `safestay --disclaimer` for the full")
	fmt.Println("text, or read DISCLAIMER.md in the source repository.")
}
