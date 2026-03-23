package tui

import "github.com/cuz/safestay/internal/model"

// DevicesDiscoveredMsg is sent when device discovery completes.
type DevicesDiscoveredMsg struct {
	Devices []*model.Device
}

// DeviceScanCompleteMsg is sent when port scanning completes for one device.
type DeviceScanCompleteMsg struct {
	Device *model.Device
}

// ScanStatusMsg updates the status bar during scanning.
type ScanStatusMsg struct {
	Text string
}

// NoDevicesMsg is sent when discovery succeeds but returns no devices.
type NoDevicesMsg struct {
	Reason string
}

// ScanFinishedMsg is sent when all scanning is complete.
type ScanFinishedMsg struct {
	Total  int
	High   int
	Medium int
	Low    int
}

// ErrorMsg carries an error to display.
type ErrorMsg struct {
	Err error
}
