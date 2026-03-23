package oui

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed mac-vendors.txt
var macVendorsData string

var (
	fallbackDB   map[string]string
	fallbackOnce sync.Once
)

func loadFallbackDB() {
	fallbackDB = make(map[string]string, 40000)
	for _, line := range strings.Split(macVendorsData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 1 {
			continue
		}
		prefix := strings.ToUpper(line[:idx])
		vendor := line[idx+1:]
		fallbackDB[prefix] = vendor
	}
}

// LookupFallback looks up a MAC address vendor using the embedded 38K-entry database.
func LookupFallback(mac string) string {
	fallbackOnce.Do(loadFallbackDB)

	// Normalize MAC: remove colons/dashes, take first 6 hex chars, uppercase
	cleaned := strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac)
	cleaned = strings.ToUpper(cleaned)
	if len(cleaned) >= 6 {
		cleaned = cleaned[:6]
	}

	return fallbackDB[cleaned]
}
