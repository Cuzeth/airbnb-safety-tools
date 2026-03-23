package oui

import (
	"strings"

	"github.com/cuz/safestay/internal/model"
)

// CameraOUIPrefixes maps MAC OUI prefixes (uppercase, colon-separated, e.g. "00:BC:99")
// to known camera manufacturer brand names. These get HIGH risk automatically.
var CameraOUIPrefixes = map[string]string{
	// ── Hikvision (81 prefixes) ──────────────────────────────────────
	"00:BC:99": "Hikvision", "04:03:12": "Hikvision", "04:EE:CD": "Hikvision",
	"08:3B:C1": "Hikvision", "08:54:11": "Hikvision", "08:A1:89": "Hikvision",
	"08:CC:81": "Hikvision", "0C:75:D2": "Hikvision", "10:12:FB": "Hikvision",
	"18:68:CB": "Hikvision", "18:80:25": "Hikvision", "24:0F:9B": "Hikvision",
	"24:28:FD": "Hikvision", "24:32:AE": "Hikvision", "24:48:45": "Hikvision",
	"28:57:BE": "Hikvision", "2C:A5:9C": "Hikvision", "34:09:62": "Hikvision",
	"3C:1B:F8": "Hikvision", "40:AC:BF": "Hikvision", "44:19:B6": "Hikvision",
	"44:47:CC": "Hikvision", "44:A6:42": "Hikvision", "48:78:5B": "Hikvision",
	"4C:1F:86": "Hikvision", "4C:62:DF": "Hikvision", "4C:BD:8F": "Hikvision",
	"4C:F5:DC": "Hikvision", "50:E5:38": "Hikvision", "54:8C:81": "Hikvision",
	"54:C4:15": "Hikvision", "58:03:FB": "Hikvision", "58:50:ED": "Hikvision",
	"5C:34:5B": "Hikvision", "64:DB:8B": "Hikvision", "68:6D:BC": "Hikvision",
	"74:3F:C2": "Hikvision", "80:48:9F": "Hikvision", "80:7C:62": "Hikvision",
	"80:BE:AF": "Hikvision", "80:F5:AE": "Hikvision", "84:94:59": "Hikvision",
	"84:9A:40": "Hikvision", "88:DE:39": "Hikvision", "8C:22:D2": "Hikvision",
	"8C:E7:48": "Hikvision", "94:E1:AC": "Hikvision", "98:8B:0A": "Hikvision",
	"98:9D:E5": "Hikvision", "98:DF:82": "Hikvision", "98:F1:12": "Hikvision",
	"A0:FF:0C": "Hikvision", "A4:14:37": "Hikvision", "A4:29:02": "Hikvision",
	"A4:4B:D9": "Hikvision", "A4:A4:59": "Hikvision", "A4:D5:C2": "Hikvision",
	"AC:B9:2F": "Hikvision", "AC:CB:51": "Hikvision", "B4:A3:82": "Hikvision",
	"BC:5E:33": "Hikvision", "BC:9B:5E": "Hikvision", "BC:AD:28": "Hikvision",
	"BC:BA:C2": "Hikvision", "C0:51:7E": "Hikvision", "C0:56:E3": "Hikvision",
	"C0:6D:ED": "Hikvision", "C4:2F:90": "Hikvision", "C8:A7:02": "Hikvision",
	"D4:E8:53": "Hikvision", "DC:07:F8": "Hikvision", "DC:D2:6A": "Hikvision",
	"E0:BA:AD": "Hikvision", "E0:CA:3C": "Hikvision", "E0:DF:13": "Hikvision",
	"E4:D5:8B": "Hikvision", "E8:A0:ED": "Hikvision", "EC:A9:71": "Hikvision",
	"EC:C8:9C": "Hikvision", "F8:4D:FC": "Hikvision", "FC:9F:FD": "Hikvision",
	// ── Dahua (27 prefixes) ──────────────────────────────────────────
	"08:ED:ED": "Dahua", "14:A7:8B": "Dahua", "24:52:6A": "Dahua",
	"38:AF:29": "Dahua", "3C:E3:6B": "Dahua", "3C:EF:8C": "Dahua",
	"4C:11:BF": "Dahua", "5C:F5:1A": "Dahua", "64:FD:29": "Dahua",
	"6C:1C:71": "Dahua", "74:C9:29": "Dahua", "8C:E9:B4": "Dahua",
	"90:02:A9": "Dahua", "98:F9:CC": "Dahua", "9C:14:63": "Dahua",
	"A0:BD:1D": "Dahua", "B4:4C:3B": "Dahua", "BC:32:5F": "Dahua",
	"C0:39:5A": "Dahua", "C4:AA:C4": "Dahua", "D4:43:0E": "Dahua",
	"E0:2E:FE": "Dahua", "E0:50:8B": "Dahua", "E4:24:6C": "Dahua",
	"F4:B1:C2": "Dahua", "FC:5F:49": "Dahua", "FC:B6:9D": "Dahua",
	// ── Wyze (6 prefixes) ────────────────────────────────────────────
	"2C:AA:8E": "Wyze", "7C:78:B2": "Wyze", "80:48:2C": "Wyze",
	"A4:DA:22": "Wyze", "D0:3F:27": "Wyze", "F0:C8:8B": "Wyze",
	// ── Ring (12 prefixes) ───────────────────────────────────────────
	"00:B4:63": "Ring", "18:7F:88": "Ring", "24:2B:D6": "Ring",
	"34:3E:A4": "Ring", "54:E0:19": "Ring", "5C:47:5E": "Ring",
	"64:9A:63": "Ring", "90:48:6C": "Ring", "9C:76:13": "Ring",
	"AC:9F:C3": "Ring", "C4:DB:AD": "Ring", "CC:3B:FB": "Ring",
	// ── Axis Communications ──────────────────────────────────────────
	"00:40:8C": "Axis", "AC:CC:8E": "Axis", "B8:A4:4F": "Axis",
	// ── Foscam ───────────────────────────────────────────────────────
	"C0:61:18": "Foscam", "00:0D:C5": "Foscam",
	// ── Amcrest ──────────────────────────────────────────────────────
	"9C:8E:CD": "Amcrest", "A0:60:32": "Amcrest",
	"00:65:1E": "Amcrest", "34:46:63": "Amcrest",
	// ── Reolink ──────────────────────────────────────────────────────
	"EC:71:DB": "Reolink", "B4:6D:83": "Reolink",
	// ── Arlo ─────────────────────────────────────────────────────────
	"48:62:64": "Arlo", "A4:11:62": "Arlo", "FC:9C:98": "Arlo",
	"20:3D:BD": "Arlo", "6C:4A:85": "Arlo", "9C:E6:35": "Arlo",
	// ── Vivotek ──────────────────────────────────────────────────────
	"00:02:D1": "Vivotek",
	// ── Uniview ──────────────────────────────────────────────────────
	"24:24:05": "Uniview",
	// ── TP-Link / Tapo cameras ───────────────────────────────────────
	"60:32:B1": "TP-Link/Tapo", "98:25:4A": "TP-Link/Tapo",
	// ── Nest (Google) ────────────────────────────────────────────────
	"18:B4:30": "Nest", "64:16:66": "Nest",
	// ── Hanwha Techwin / Wisenet ─────────────────────────────────────
	"00:09:18": "Hanwha/Wisenet", "00:16:63": "Hanwha/Wisenet",
	// ── FLIR ─────────────────────────────────────────────────────────
	"00:40:7F": "FLIR",
	// ── Xiongmai / XMEye ─────────────────────────────────────────────
	"00:12:12": "Xiongmai/XMEye", "00:12:13": "Xiongmai/XMEye",
	"00:12:14": "Xiongmai/XMEye", "00:12:15": "Xiongmai/XMEye",
	"00:12:16": "Xiongmai/XMEye", "00:12:17": "Xiongmai/XMEye",
	"00:12:10": "Xiongmai/XMEye", "00:12:11": "Xiongmai/XMEye",
	// ── Ubiquiti / UniFi ─────────────────────────────────────────────
	"24:5A:4C": "Ubiquiti/UniFi", "68:D7:9A": "Ubiquiti/UniFi",
	"74:83:C2": "Ubiquiti/UniFi", "78:8A:20": "Ubiquiti/UniFi",
	"80:2A:A8": "Ubiquiti/UniFi", "B4:FB:E4": "Ubiquiti/UniFi",
	"F0:9F:C2": "Ubiquiti/UniFi", "FC:EC:DA": "Ubiquiti/UniFi",
}

// ChipsetOUIPrefixes maps MAC prefixes to WiFi chipset vendors.
// These are MEDIUM risk (not camera brands, but commonly found inside hidden cameras).
var ChipsetOUIPrefixes = map[string]string{
	"00:E0:4C": "Realtek [WiFi module]",
	"52:54:00": "Realtek [WiFi module]",
	"00:0C:43": "MediaTek/Ralink [WiFi module]",
	"00:0C:E7": "MediaTek [WiFi module]",
	"00:0A:00": "MediaTek [WiFi module]",
	"00:17:A5": "MediaTek [WiFi module]",
}

// VendorCategoryEntry holds the category and risk for a vendor name match.
type VendorCategoryEntry struct {
	Category model.DeviceCategory
	Risk     model.RiskLevel
}

// VendorCategoryMap maps lowercase vendor name substrings to category+risk.
var VendorCategoryMap = map[string]VendorCategoryEntry{
	// HIGH risk - camera/surveillance companies
	"hikvision":          {model.CategoryCamera, model.RiskHigh},
	"dahua":              {model.CategoryCamera, model.RiskHigh},
	"wyze":               {model.CategoryCamera, model.RiskHigh},
	"ring":               {model.CategoryCamera, model.RiskHigh},
	"axis communications": {model.CategoryCamera, model.RiskHigh},
	"foscam":             {model.CategoryCamera, model.RiskHigh},
	"amcrest":            {model.CategoryCamera, model.RiskHigh},
	"reolink":            {model.CategoryCamera, model.RiskHigh},
	"vivotek":            {model.CategoryCamera, model.RiskHigh},
	"uniview":            {model.CategoryCamera, model.RiskHigh},
	"arlo":               {model.CategoryCamera, model.RiskHigh},
	"eufy":               {model.CategoryCamera, model.RiskHigh},
	"anker innovations":  {model.CategoryCamera, model.RiskHigh},
	"nest":               {model.CategoryCamera, model.RiskHigh},
	"ubiquiti":           {model.CategoryCamera, model.RiskMedium},
	"hanwha":             {model.CategoryCamera, model.RiskHigh},
	"wisenet":            {model.CategoryCamera, model.RiskHigh},
	"flir":               {model.CategoryCamera, model.RiskHigh},
	"lorex":              {model.CategoryCamera, model.RiskHigh},
	"swann":              {model.CategoryCamera, model.RiskHigh},
	"xiongmai":           {model.CategoryCamera, model.RiskHigh},
	"xmeye":              {model.CategoryCamera, model.RiskHigh},
	"tapo":               {model.CategoryCamera, model.RiskHigh},
	"jovision":           {model.CategoryCamera, model.RiskHigh},
	// MEDIUM risk - chipset vendors
	"realtek":   {model.CategoryIOT, model.RiskMedium},
	"ralink":    {model.CategoryIOT, model.RiskMedium},
	"mediatek":  {model.CategoryIOT, model.RiskMedium},
	"anyka":     {model.CategoryCamera, model.RiskHigh},
	"goke":      {model.CategoryCamera, model.RiskHigh},
	"ingenic":   {model.CategoryCamera, model.RiskHigh},
	"hisilicon": {model.CategoryIOT, model.RiskMedium},
	// MEDIUM risk - IoT / smart home
	"amazon":    {model.CategorySmartSpeaker, model.RiskMedium},
	"google":    {model.CategorySmartHome, model.RiskMedium},
	"apple":     {model.CategoryPhone, model.RiskLow},
	"sonos":     {model.CategorySmartSpeaker, model.RiskMedium},
	"tuya":      {model.CategoryIOT, model.RiskMedium},
	"shelly":    {model.CategoryIOT, model.RiskMedium},
	"espressif": {model.CategoryIOT, model.RiskMedium},
	"tp-link":   {model.CategoryIOT, model.RiskMedium},
	"samsung":   {model.CategoryTV, model.RiskLow},
	"lg electronics": {model.CategoryTV, model.RiskLow},
	"roku":      {model.CategoryTV, model.RiskLow},
	// LOW risk - common devices
	"intel":     {model.CategoryComputer, model.RiskLow},
	"dell":      {model.CategoryComputer, model.RiskLow},
	"lenovo":    {model.CategoryComputer, model.RiskLow},
	"hewlett":   {model.CategoryComputer, model.RiskLow},
	"microsoft": {model.CategoryComputer, model.RiskLow},
	// Routers
	"netgear":  {model.CategoryRouter, model.RiskLow},
	"linksys":  {model.CategoryRouter, model.RiskLow},
	"asus":     {model.CategoryRouter, model.RiskLow},
	"arris":    {model.CategoryRouter, model.RiskLow},
	"cisco":    {model.CategoryRouter, model.RiskLow},
	"motorola": {model.CategoryRouter, model.RiskLow},
}

// LookupOUIPrefix checks if a MAC matches a known camera manufacturer.
func LookupOUIPrefix(mac string) string {
	prefix := strings.ToUpper(mac)
	if len(prefix) >= 8 {
		prefix = prefix[:8]
	}
	return CameraOUIPrefixes[prefix]
}

// LookupChipsetPrefix checks if a MAC matches a known WiFi chipset vendor.
func LookupChipsetPrefix(mac string) string {
	prefix := strings.ToUpper(mac)
	if len(prefix) >= 8 {
		prefix = prefix[:8]
	}
	return ChipsetOUIPrefixes[prefix]
}

// LookupAnyPrefix checks camera brands first, then chipset vendors.
func LookupAnyPrefix(mac string) string {
	if brand := LookupOUIPrefix(mac); brand != "" {
		return brand
	}
	return LookupChipsetPrefix(mac)
}

// CategorizeByVendor matches a vendor name against known categories.
func CategorizeByVendor(vendor string) (model.DeviceCategory, model.RiskLevel, bool) {
	vendorLower := strings.ToLower(vendor)
	for keyword, entry := range VendorCategoryMap {
		if strings.Contains(vendorLower, keyword) {
			return entry.Category, entry.Risk, true
		}
	}
	return model.CategoryUnknown, model.RiskUnknown, false
}
