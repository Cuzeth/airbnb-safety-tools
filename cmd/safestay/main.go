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
const shortDisclaimer = `SafeStay is licensed under MIT — provided "AS IS", with no warranty and no
liability. It is not legal advice. The author does not condone, encourage, or
recommend its use against any network, device, host, or person. Network
scanning may be illegal in your jurisdiction — you alone are responsible for
confirming you have authorization to scan. If unsure, do not run it. See
DISCLAIMER.md for the full informational notice.`

const fullDisclaimer = `SAFESTAY — IMPORTANT INFORMATION

This software is licensed under the MIT License. The MIT license provides
the software "AS IS", WITHOUT WARRANTY OF ANY KIND, and disclaims liability
for any claim or damages arising from the software. The text below expands
on that posture; it is informational and not a separate contract.

  - The author and contributors are not liable for any damages, losses,
    criminal charges, civil claims, account termination, or other
    consequences of any kind arising from the use of this software.
  - The author does not condone, encourage, endorse, or recommend the use
    of this tool against any network, system, device, or person.
  - Nothing in this software, its documentation, or its output is legal
    advice. Always consult a licensed attorney in your jurisdiction.
  - False positives and false negatives are expected — never rely on this
    tool as the sole basis for any decision about your safety.

Network scanning, port scanning, and the techniques used by this tool may
be illegal, regulated, or restricted under your local laws and the terms
of service of the network you are connected to. You alone are responsible
for confirming you have lawful authorization to scan, before you scan.

SafeStay is not affiliated with, endorsed by, or connected to Airbnb, Vrbo,
any hotel chain, or any camera or chip manufacturer named anywhere in this
software. Vendor names appear only as technical references.

Data handling: SafeStay performs all scanning locally. It does not transmit
results to any server and does not contact third-party hosts during normal
operation. Reports written via the export command contain MAC and IP
addresses of devices on your local subnet, which may be personal data under
your jurisdiction's law. You are the data controller for any report you
generate, retain, or share.

If in doubt, do not run this software. If you believe a crime has occurred,
contact local law enforcement and a licensed attorney — not this tool.

For the full informational notice, see:
  https://github.com/Cuzeth/airbnb-safety-tools/blob/main/DISCLAIMER.md
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
	fmt.Println("  --disclaimer     Print the full informational notice and exit")
	fmt.Println()
	fmt.Println("Run with sudo for best results (lets the discovery phase send")
	fmt.Println("raw ICMP probes, putting more devices in the ARP cache).")
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
	fmt.Println("MIT-licensed. AS IS, no warranty, no liability. Not legal advice.")
	fmt.Println("The author does not condone or recommend its use. Run")
	fmt.Println("`safestay --disclaimer` for the full informational notice, or read")
	fmt.Println("DISCLAIMER.md in the source repository.")
}
