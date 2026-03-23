package model

import "sort"

// PortDatabase contains all 30 camera-specific ports with metadata.
var PortDatabase = map[int]PortInfo{
	// ── Streaming protocols ──────────────────────────────────────────
	554: {
		Port: 554, Protocol: "RTSP", Risk: RiskHigh, WebOpenable: false,
		Description: "Real Time Streaming Protocol — standard video streaming port used by " +
			"virtually all IP cameras (Hikvision, Dahua, Axis, Reolink, etc.)",
	},
	8554: {
		Port: 8554, Protocol: "RTSP-Alt", Risk: RiskHigh, WebOpenable: false,
		Description: "Alternate RTSP port — used by Zhongwei/Shangwei cameras and some " +
			"cameras configured to avoid the standard 554",
	},
	1935: {
		Port: 1935, Protocol: "RTMP", Risk: RiskHigh, WebOpenable: false,
		Description: "Real Time Messaging Protocol — used for live video streaming, " +
			"common on cameras that stream to cloud services or NVRs",
	},
	// ── Camera vendor-specific protocols ─────────────────────────────
	37777: {
		Port: 37777, Protocol: "Dahua-TCP", Risk: RiskHigh, WebOpenable: false,
		Description: "Dahua proprietary TCP control port — used by Dahua cameras, NVRs, " +
			"and Lorex rebadges for device management and video transport",
	},
	37778: {
		Port: 37778, Protocol: "Dahua-UDP", Risk: RiskHigh, WebOpenable: false,
		Description: "Dahua proprietary UDP data port — used alongside TCP/37777 for " +
			"real-time video data streaming on Dahua/Lorex devices",
	},
	8000: {
		Port: 8000, Protocol: "Hikvision-SDK", Risk: RiskHigh, WebOpenable: false,
		Description: "Hikvision iVMS/SDK service port — primary management protocol for " +
			"Hikvision cameras and NVRs, used by iVMS-4200 client software",
	},
	8200: {
		Port: 8200, Protocol: "Hikvision-SDK", Risk: RiskHigh, WebOpenable: false,
		Description: "Hikvision secondary service port — used for additional camera " +
			"management functions alongside port 8000",
	},
	6668: {
		Port: 6668, Protocol: "Wyze-TUTK", Risk: RiskHigh, WebOpenable: false,
		Description: "Wyze camera TUTK P2P protocol — used by Wyze Cam v1/v2/v3 for " +
			"peer-to-peer video streaming through their IoTCAM/TUTK SDK",
	},
	6669: {
		Port: 6669, Protocol: "Wyze-TUTK", Risk: RiskHigh, WebOpenable: false,
		Description: "Wyze camera secondary TUTK port — alternate P2P streaming port " +
			"used by Wyze devices for redundancy",
	},
	34567: {
		Port: 34567, Protocol: "XMEye/Xiongmai", Risk: RiskHigh, WebOpenable: false,
		Description: "Xiongmai (XMEye) proprietary protocol — extremely common on budget " +
			"unbranded IP cameras, DVRs, and NVRs from Chinese OEMs",
	},
	// ── Web interfaces (openable in browser) ─────────────────────────
	80: {
		Port: 80, Protocol: "HTTP", Risk: RiskMedium, WebOpenable: true, URLScheme: "http",
		Description: "HTTP web server — cameras expose admin panels here. Hikvision, " +
			"Dahua, Axis, Foscam, and most IP cameras have a web UI on port 80",
	},
	443: {
		Port: 443, Protocol: "HTTPS", Risk: RiskMedium, WebOpenable: true, URLScheme: "https",
		Description: "HTTPS web server — encrypted version of the camera admin panel. " +
			"Used by Hikvision, Reolink, and enterprise cameras",
	},
	8080: {
		Port: 8080, Protocol: "HTTP-Alt", Risk: RiskMedium, WebOpenable: true, URLScheme: "http",
		Description: "Alternate HTTP port — used when port 80 is taken. Common on cameras " +
			"behind routers, ONVIF discovery port for some brands (e.g. Tiandy)",
	},
	8443: {
		Port: 8443, Protocol: "HTTPS-Alt", Risk: RiskMedium, WebOpenable: true, URLScheme: "https",
		Description: "Alternate HTTPS port — encrypted web interface on non-standard port, " +
			"used by some cameras and NVR systems for remote management",
	},
	8899: {
		Port: 8899, Protocol: "ONVIF/XMEye", Risk: RiskHigh, WebOpenable: true, URLScheme: "http",
		Description: "Xiongmai/V380 ONVIF port — used for device discovery and management " +
			"on budget cameras. May expose a basic web interface",
	},
	// ── NAS / Surveillance station ───────────────────────────────────
	5000: {
		Port: 5000, Protocol: "HTTP-NAS", Risk: RiskMedium, WebOpenable: true, URLScheme: "http",
		Description: "Synology DSM / surveillance station HTTP — used by Synology NAS " +
			"running Surveillance Station, also used by some ONVIF cameras (Yoosee)",
	},
	5001: {
		Port: 5001, Protocol: "HTTPS-NAS", Risk: RiskMedium, WebOpenable: true, URLScheme: "https",
		Description: "Synology DSM / surveillance station HTTPS — encrypted management " +
			"interface for Synology NAS with Surveillance Station",
	},
	// ── P2P / NAT traversal ──────────────────────────────────────────
	3478: {
		Port: 3478, Protocol: "STUN/TURN", Risk: RiskMedium, WebOpenable: false,
		Description: "STUN/TURN for WebRTC NAT traversal — used by cameras that stream " +
			"through cloud services (Ring, Nest, Arlo) to punch through firewalls",
	},
	// ── General camera management ────────────────────────────────────
	9000: {
		Port: 9000, Protocol: "Camera-Mgmt", Risk: RiskMedium, WebOpenable: true, URLScheme: "http",
		Description: "Camera management port — used by various brands for secondary " +
			"management interfaces, API endpoints, or ONVIF services",
	},
	// ── Additional discovery ports ───────────────────────────────────
	2000: {
		Port: 2000, Protocol: "ONVIF", Risk: RiskMedium, WebOpenable: false,
		Description: "ONVIF device discovery — used by Dragon/JVT cameras for ONVIF " +
			"device management and discovery",
	},
	3702: {
		Port: 3702, Protocol: "WS-Discovery", Risk: RiskMedium, WebOpenable: false,
		Description: "WS-Discovery / ONVIF — used by TECH/YOOSEE cameras for network " +
			"device discovery via Web Services Dynamic Discovery protocol",
	},
	8091: {
		Port: 8091, Protocol: "Tianshitong", Risk: RiskHigh, WebOpenable: false,
		Description: "Tianshitong/TOPSEE data port — proprietary data channel used by " +
			"TOPSEE branded IP cameras for video transport",
	},
	// ── Hidden camera / spy camera ports ─────────────────────────────
	32100: {
		Port: 32100, Protocol: "CS2/PPPP", Risk: RiskHigh, WebOpenable: false,
		Description: "CS2 Network P2P protocol (PPPP) — the primary port used by hidden " +
			"spy cameras (LookCam, V380, VRCAM). Uses UDP hole-punching for NAT " +
			"traversal. A response on this port is a very strong indicator of a " +
			"hidden camera. Common on Anyka AK3918-based modules",
	},
	10554: {
		Port: 10554, Protocol: "RTSP-Alt", Risk: RiskHigh, WebOpenable: false,
		Description: "Alternate RTSP port — commonly used by cheap WIFICAM-type hidden " +
			"cameras and GoAhead-based firmware. Often unauthenticated, allowing " +
			"direct video stream access without credentials",
	},
	23: {
		Port: 23, Protocol: "Telnet", Risk: RiskHigh, WebOpenable: false,
		Description: "Telnet — debug/backdoor access left enabled on many cheap Chinese " +
			"cameras. Indicates a low-quality IoT device with poor security. " +
			"Common default credentials: root/xmhdipc, root/xc3511, root/123456",
	},
	9527: {
		Port: 9527, Protocol: "XM-Console", Risk: RiskHigh, WebOpenable: false,
		Description: "Xiongmai debug console — telnet-like backdoor on Xiongmai/XMEye " +
			"cameras and DVRs. Allows remote command execution. Strong indicator " +
			"of a cheap surveillance device",
	},
	81: {
		Port: 81, Protocol: "HTTP-Alt", Risk: RiskMedium, WebOpenable: true, URLScheme: "http",
		Description: "Alternate HTTP port — very common on cheap IP cameras that use port " +
			"81 instead of 80 for their web interface. Check for GoAhead server " +
			"or camera-specific paths (/system.ini, /snapshot.jpg)",
	},
	// ── Additional P2P / cloud camera ports ──────────────────────────
	8600: {
		Port: 8600, Protocol: "TUTK-P2P", Risk: RiskHigh, WebOpenable: false,
		Description: "ThroughTek TUTK P2P relay — used by 50M+ IoT devices including " +
			"many hidden cameras. Part of the Kalay P2P platform that enables " +
			"cloud streaming without exposing local RTSP",
	},
}

// CameraPorts is a sorted list of all ports to scan.
var CameraPorts []int

func init() {
	CameraPorts = make([]int, 0, len(PortDatabase))
	for port := range PortDatabase {
		CameraPorts = append(CameraPorts, port)
	}
	sort.Ints(CameraPorts)
}
