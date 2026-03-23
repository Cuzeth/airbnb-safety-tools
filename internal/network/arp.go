package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cuz/safestay/internal/model"
)

// ARPScan discovers devices by probing the subnet then reading the ARP cache.
// The probe phase populates the OS ARP table; we then read it.
func ARPScan(subnet string) ([]*model.Device, error) {
	pingSweep(subnet)
	return readARPCache()
}

// pingSweep probes all IPs in the subnet to populate the ARP cache.
//
// To match nmap -sn coverage, we use multiple methods:
//   - ICMP echo (if root on Unix, or on macOS via /sbin/ping)
//   - TCP SYN connect to ports 80, 443, 22, 8080, 554, 5000 (catches cameras, NAS, routers)
//   - UDP probe to port 5353 (mDNS — catches Apple devices, Chromecasts, smart speakers)
//
// All probes run concurrently. Even if a device doesn't respond, the kernel
// still performs ARP resolution, so the MAC appears in the ARP cache.
func pingSweep(subnet string) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return
	}

	ips := allIPsInSubnet(ipNet)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 128)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			probeHost(ip)
		}(ip)
	}
	wg.Wait()
}

// probeHost tries multiple methods to trigger an ARP entry for one IP.
func probeHost(ip string) {
	timeout := 800 * time.Millisecond

	// 1. ICMP echo via unprivileged UDP "ping" — works on Linux (net.ipv4.ping_group_range),
	//    and on macOS where ICMP is allowed for non-root.
	//    Even if the ICMP packet is dropped, the kernel still does ARP.
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err == nil {
		// Send a minimal echo request
		icmpEcho := []byte{
			8, 0, // Type: Echo Request, Code: 0
			0, 0, // Checksum (filled below)
			0, 1, // Identifier
			0, 1, // Sequence number
		}
		// Compute checksum
		csum := icmpChecksum(icmpEcho)
		icmpEcho[2] = byte(csum >> 8)
		icmpEcho[3] = byte(csum)
		conn.SetDeadline(time.Now().Add(timeout))
		conn.Write(icmpEcho)
		buf := make([]byte, 64)
		conn.Read(buf)
		conn.Close()
	}

	// 2. TCP connect probes to common ports — triggers ARP even if port is closed
	//    (the kernel sends ARP to resolve the MAC before sending the SYN).
	//    Ports chosen to cover: web servers, cameras (554 RTSP), NAS (5000),
	//    SSH (22), alt-HTTP (8080), and IoT management.
	tcpPorts := []int{80, 443, 22, 8080, 554, 5000, 23, 34567}
	for _, port := range tcpPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
		if err == nil {
			conn.Close()
			return // Device found, no need to probe more
		}
	}

	// 3. UDP probe to mDNS (5353) — catches Apple devices, Chromecasts, Sonos, etc.
	//    Doesn't need a response; the kernel does ARP to send the UDP packet.
	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "5353"))
	if err == nil {
		udpConn, err := net.DialUDP("udp4", nil, udpAddr)
		if err == nil {
			udpConn.SetDeadline(time.Now().Add(timeout))
			udpConn.Write([]byte{0}) // minimal probe
			udpConn.Close()
		}
	}
}

// icmpChecksum computes the ICMP checksum for a message.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// readARPCache reads the OS ARP cache and returns discovered devices.
func readARPCache() ([]*model.Device, error) {
	switch runtime.GOOS {
	case "linux":
		return readLinuxARP()
	default:
		return readUnixARP()
	}
}

// readLinuxARP parses /proc/net/arp.
func readLinuxARP() ([]*model.Device, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return readUnixARP()
	}
	defer f.Close()

	var devices []*model.Device
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := strings.ToUpper(fields[3])
		if mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		seen[mac] = true
		devices = append(devices, &model.Device{
			IP:        ip,
			MAC:       mac,
			Vendor:    "Unknown",
			RiskLevel: model.RiskUnknown,
			Category:  model.CategoryUnknown,
		})
	}
	return devices, nil
}

// readUnixARP parses the output of `arp -a` (macOS, BSD, Windows).
func readUnixARP() ([]*model.Device, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("arp -a failed: %w", err)
	}

	var devices []*model.Device
	seen := make(map[string]bool)
	macRe := regexp.MustCompile(`([0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2})`)
	ipRe := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)`)

	for _, line := range strings.Split(string(out), "\n") {
		ipMatch := ipRe.FindStringSubmatch(line)
		macMatch := macRe.FindStringSubmatch(line)
		if ipMatch == nil || macMatch == nil {
			continue
		}

		ip := ipMatch[1]
		mac := normalizeMACAddress(macMatch[1])
		if mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" || seen[mac] {
			continue
		}
		seen[mac] = true
		devices = append(devices, &model.Device{
			IP:        ip,
			MAC:       mac,
			Vendor:    "Unknown",
			RiskLevel: model.RiskUnknown,
			Category:  model.CategoryUnknown,
		})
	}
	return devices, nil
}

// normalizeMACAddress normalizes a MAC address to uppercase colon-separated format.
func normalizeMACAddress(mac string) string {
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
		parts[i] = strings.ToUpper(parts[i])
	}
	return strings.Join(parts, ":")
}

// allIPsInSubnet returns all host IPs in a /24 subnet (excluding network and broadcast).
func allIPsInSubnet(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.To4()
	if ip == nil {
		return ips
	}
	for i := 1; i < 255; i++ {
		host := make(net.IP, 4)
		copy(host, ip)
		host[3] = byte(i)
		ips = append(ips, host.String())
	}
	return ips
}
