// Package guide provides shared, non-technical safety content that is consumed
// by both the TUI (the "press ? for help" overlay) and the exported HTML report.
//
// The detection model in fingerprint/ scans the WiFi network. That misses an
// entire class of real-world threats: cameras on a separate guest VLAN,
// cameras that use a 4G/LTE SIM and never touch the host WiFi, SD-card-only
// recorders, and any device a network with AP isolation hides from us. So the
// network result is never a "safe / not safe" answer on its own — it must be
// paired with a physical sweep and a clear next-step path if anything turns
// up. This package owns that content so we only have to maintain it once.
package guide

// PhysicalCheck is the room-walkthrough a guest can do without any tool.
// Ordered roughly by where cameras are most commonly found in Airbnb cases.
var PhysicalCheck = []Section{
	{
		Title: "Look at the obvious spots first",
		Items: []string{
			"Smoke detectors, especially ones placed unusually low or aimed at a bed",
			"Air purifiers, alarm clocks, picture frames, mirrors, decorative plants",
			"USB chargers and power adapters plugged into outlets near the bed or shower",
			"Vents, speakers, and any object with a small dark dot the size of a pencil tip",
		},
	},
	{
		Title: "Sweep the room with a flashlight in the dark",
		Items: []string{
			"Turn off all lights and close the curtains",
			"Use a flashlight (phone torch works) and slowly sweep across surfaces from eye level",
			"A camera lens reflects a sharp, repeatable glint — different from glass or metal",
			"Inspect any glint up close: lift, twist, or unscrew the object if you can",
		},
	},
	{
		Title: "Use your phone's front camera to find IR LEDs",
		Items: []string{
			"Open your phone's front-facing camera (not the rear — most rear cameras filter IR)",
			"Turn off the room lights. Point it at smoke detectors, vents, clocks, frames",
			"Night-vision cameras emit faint purple/white dots that are invisible to the eye but visible to your phone sensor",
			"If you see steady IR dots from an object that should not have a camera, treat it as a finding",
		},
	},
	{
		Title: "Check for cameras that don't use the WiFi",
		Items: []string{
			"4G/LTE cameras have a SIM card and bypass the host network entirely — SafeStay cannot see them",
			"Look for objects with an unusual second power cable, or a small antenna nub",
			"SD-card recorders need no network at all — they just store video locally",
			"If you find a device you cannot explain, document it before touching it further",
		},
	},
}

// IfYouFoundSomething is the post-detection script. The goal is to remove the
// "now what?" moment after a HIGH-risk finding or a physical discovery. Order
// matters: do not confront the host first; preserve evidence and your
// rebooking/refund eligibility instead.
var IfYouFoundSomething = []Section{
	{
		Title: "1. Do not confront the host",
		Items: []string{
			"You are in their property, possibly far from home. Stay calm",
			"Do not unplug, cover, or move the device beyond what you need for one clear photo",
			"Do not message the host with accusations from inside the unit",
		},
	},
	{
		Title: "2. Document it before you do anything else",
		Items: []string{
			"Take timestamped photos and a short video showing the device's location in the room",
			"Capture the SafeStay report (press 'e' to export an HTML report you can attach)",
			"Note the listing URL, host name, and the exact check-in and check-out times",
		},
	},
	{
		Title: "3. Leave the unit if you feel unsafe, then call the police",
		Items: []string{
			"Per Airbnb's guidance, call local police before contacting Airbnb support",
			"Get a report number — Airbnb's resolution team will ask for it",
			"If you are in another country, search for the local non-emergency police line, not 911",
		},
	},
	{
		Title: "4. Report to Airbnb within 72 hours",
		Items: []string{
			"Open the Airbnb Resolution Center: https://www.airbnb.com/help/article/3061",
			"Hidden cameras anywhere inside a listing have been banned by Airbnb since April 2024",
			"Reporting within 72 hours preserves your eligibility for a full or partial refund and rebooking",
			"Attach: your photos, the police report number, and the SafeStay HTML report",
		},
	},
	{
		Title: "5. After the stay",
		Items: []string{
			"Check your devices for unfamiliar pairings — some hostile setups pair over Bluetooth",
			"Consider posting a review only after Airbnb's investigation closes (their TOS limits review edits)",
			"If a crime occurred, your police report — not just the Airbnb report — is what carries forward",
		},
	},
}

// Limits explains, in plain language, what the network scan cannot see.
// This is the disclaimer that should appear next to any "no high risk" result.
var Limits = []string{
	"Cameras on a 4G/LTE SIM card are invisible to any WiFi scan",
	"AP / client isolation hides every other device on the network from this tool",
	"Cameras that only write to an SD card and never go online cannot be detected",
	"Modern hidden cameras often run unbranded firmware on commodity chips (Tuya, ESP32, Anyka, Ingenic) — they may not match any known vendor",
	"This tool is a starting point, not a guarantee. Always pair it with a physical sweep",
}

// LegalNotice is the short legal disclaimer rendered at the bottom of the
// in-app guide and the HTML report. It is intentionally blunt: this software
// is not legal advice, the author accepts no liability, and the user is the
// only person responsible for whether running the scan is legal in their
// situation.
var LegalNotice = []string{
	"This tool is provided AS IS, with NO WARRANTY and NO LIABILITY. The author accepts no responsibility for any consequences of its use.",
	"Nothing in this tool, this guide, or its exported report is legal advice. Contact a licensed attorney in your jurisdiction for actual legal advice.",
	"The author does NOT condone, encourage, or recommend running this tool against any network, device, host, or person.",
	"Network scanning may be illegal where you are. You alone are responsible for confirming you have authorization to scan before you scan.",
	"SafeStay is not affiliated with Airbnb, any hotel chain, or any camera vendor. Vendor names appear as technical references only.",
	"For the full legal notice, see DISCLAIMER.md in the source repository or run `safestay --disclaimer`.",
}

// Section is one heading + a list of bullet items.
type Section struct {
	Title string
	Items []string
}
