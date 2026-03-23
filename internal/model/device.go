package model

import "fmt"

// RiskLevel indicates how suspicious a device is.
type RiskLevel string

const (
	RiskHigh    RiskLevel = "high"
	RiskMedium  RiskLevel = "medium"
	RiskLow     RiskLevel = "low"
	RiskUnknown RiskLevel = "unknown"
)

// Label returns the uppercase display label for a risk level.
func (r RiskLevel) Label() string {
	switch r {
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	case RiskLow:
		return "LOW"
	default:
		return "?"
	}
}

// DeviceCategory classifies a network device.
type DeviceCategory string

const (
	CategoryCamera       DeviceCategory = "Camera/DVR"
	CategorySmartSpeaker DeviceCategory = "Smart Speaker"
	CategorySmartHome    DeviceCategory = "Smart Home Hub"
	CategoryRouter       DeviceCategory = "Router/AP"
	CategoryPhone        DeviceCategory = "Phone/Tablet"
	CategoryComputer     DeviceCategory = "Computer"
	CategoryTV           DeviceCategory = "Smart TV"
	CategoryIOT          DeviceCategory = "IoT Device"
	CategoryUnknown      DeviceCategory = "Unknown"
)

// PortInfo holds metadata about a specific network port.
type PortInfo struct {
	Port        int
	Protocol    string
	Description string
	Risk        RiskLevel
	WebOpenable bool
	URLScheme   string // "http", "https", "rtsp", or ""
}

// URLFor returns the full URL for opening this port on a given IP.
func (p PortInfo) URLFor(ip string) string {
	if !p.WebOpenable || p.URLScheme == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s:%d/", p.URLScheme, ip, p.Port)
}

// Device represents a discovered network device.
type Device struct {
	IP           string
	MAC          string
	Vendor       string
	Hostname     string
	OpenPorts    []int
	RiskLevel    RiskLevel
	Category     DeviceCategory
	RiskReasons  []string
	ScanComplete bool
}

// Clone returns a deep copy of the device so background work can safely
// operate on a snapshot without racing the UI.
func (d *Device) Clone() *Device {
	if d == nil {
		return nil
	}

	clone := *d
	if d.OpenPorts != nil {
		clone.OpenPorts = append([]int(nil), d.OpenPorts...)
	}
	if d.RiskReasons != nil {
		clone.RiskReasons = append([]string(nil), d.RiskReasons...)
	}

	return &clone
}

// GetPortInfo returns metadata for a specific port, or nil.
func (d *Device) GetPortInfo(port int) *PortInfo {
	if info, ok := PortDatabase[port]; ok {
		return &info
	}
	return nil
}

// PortURL pairs a port number with its browser-openable URL.
type PortURL struct {
	Port int
	URL  string
}

// GetOpenablePorts returns ports that can be opened in a browser.
func (d *Device) GetOpenablePorts() []PortURL {
	var result []PortURL
	for _, port := range d.OpenPorts {
		info, ok := PortDatabase[port]
		if ok && info.WebOpenable && info.URLScheme != "" {
			result = append(result, PortURL{
				Port: port,
				URL:  info.URLFor(d.IP),
			})
		}
	}
	return result
}
