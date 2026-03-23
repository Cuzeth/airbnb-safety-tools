package scan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/cuz/safestay/internal/model"
)

// ScanPorts performs a concurrent TCP connect scan on the given IP.
// Returns a sorted list of open port numbers.
func ScanPorts(ip string, ports []int) []int {
	if ports == nil {
		ports = model.CameraPorts
	}

	var (
		mu        sync.Mutex
		openPorts []int
		wg        sync.WaitGroup
	)

	// Semaphore to limit concurrent connections
	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			openPorts = append(openPorts, p)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
}
