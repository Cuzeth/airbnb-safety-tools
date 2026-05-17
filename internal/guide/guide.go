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

// IfYouFoundSomething summarises publicly-available guidance from Airbnb's
// own help articles and widely-cited safety reporting. It is NOT advice from
// the author of this software and should not be read that way — the framing
// is deliberately third-person ("Airbnb's policy states X") rather than
// imperative ("do X"). Personal safety decisions are not addressed here at
// all; those belong with local authorities and licensed counsel, not a CLI
// tool. See LegalNotice below.
var IfYouFoundSomething = []Section{
	{
		Title: "1. The host (per published safety reporting)",
		Items: []string{
			"Widely-cited safety articles describe on-site confrontation as a common source of escalation, particularly for travellers far from home.",
			"Published accounts also describe unplugging or moving suspected devices as a frequent cause of lost evidence — one photo of the device in place is typically preserved first.",
			"Accusatory messaging from inside the unit is commonly described as counter-productive in the same accounts.",
		},
	},
	{
		Title: "2. Documentation (per Airbnb's resolution flow)",
		Items: []string{
			"Airbnb's resolution submissions typically request timestamped photos and short video showing the device's location.",
			"SafeStay can export an HTML report (press 'e') that can be attached as one piece of evidence among others.",
			"The listing URL, host name, and exact check-in/check-out times are commonly requested.",
		},
	},
	{
		Title: "3. Local authorities (per Airbnb's guidance)",
		Items: []string{
			"Airbnb's published guidance directs guests to contact local police before contacting Airbnb support.",
			"Police reports typically generate a reference number; Airbnb's resolution team commonly asks for it.",
			"Outside one's home country, the non-emergency police line varies by city — local search results are usually more accurate than 911.",
		},
	},
	{
		Title: "4. Airbnb's resolution centre",
		Items: []string{
			"Airbnb Resolution Center: https://www.airbnb.com/help/article/3061",
			"Per Airbnb's policy, hidden cameras anywhere inside a listing have been prohibited since April 2024.",
			"Per Airbnb's published terms, reporting within 72 hours of discovery is associated with eligibility for refund and rebooking.",
			"Typical submission contents per Airbnb's flow: photos, police report number, any scan report or evidence.",
		},
	},
	{
		Title: "5. After the stay (per security reporting)",
		Items: []string{
			"Security-research articles note that some hostile setups pair over Bluetooth, and that a post-stay device check is occasionally recommended.",
			"Airbnb's terms place limits on review edits once an investigation closes; published guidance often suggests waiting on a review until the platform's process completes.",
			"In jurisdictions where a crime is alleged, the police report rather than the platform report is typically what is referenced in subsequent legal proceedings.",
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
