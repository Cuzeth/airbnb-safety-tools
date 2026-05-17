// Package guide provides shared, non-technical safety content that is consumed
// by both the TUI (the "press ? for help" overlay) and the exported HTML report.
//
// The detection model in fingerprint/ scans the WiFi network. That misses an
// entire class of real-world threats: cameras on a separate guest VLAN,
// cameras that use a 4G/LTE SIM and never touch the host WiFi, SD-card-only
// recorders, and any device a network with AP isolation hides from us. So the
// network result is never a "safe / not safe" answer on its own — it must be
// paired with a physical sweep. This package owns that content so we only have
// to maintain it once.
package guide

// PhysicalCheck is the room-walkthrough a guest can do without any tool.
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

// Limits explains, in plain language, what the network scan cannot see.
var Limits = []string{
	"Cameras on a 4G/LTE SIM card are invisible to any WiFi scan",
	"AP / client isolation hides every other device on the network from this tool",
	"Cameras that only write to an SD card and never go online cannot be detected",
	"Modern hidden cameras often run unbranded firmware on commodity chips (Tuya, ESP32, Anyka, Ingenic) — they may not match any known vendor",
	"This tool is a starting point, not a guarantee. Always pair it with a physical sweep",
}

// LegalNotice is the short notice rendered at the bottom of the in-app guide
// and the HTML report.
var LegalNotice = []string{
	"MIT-licensed. AS IS, no warranty, no liability. Not legal advice. Use at your own risk.",
	"Vendor labels are derived from MAC OUI lookup — technical references, not confirmed identifications. MAC addresses can be spoofed.",
}

// Section is one heading + a list of bullet items.
type Section struct {
	Title string
	Items []string
}
