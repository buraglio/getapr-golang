package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Constants for Happy Eyeballs configuration
const (
	DefaultPort            = 80
	DefaultTimeout         = 2 * time.Second
	DefaultResolutionDelay = 50 * time.Millisecond
)

// AddrPair contains all information about a source-destination pair
type AddrPair struct {
	Source        net.IP
	SourceZone    string
	Dest          net.IP
	DestZone      string
	Latency       time.Duration
	Attempts      int
	LastAttempt   time.Time
	SameNetwork   bool
	AddressFamily int
	DNSSECValid   bool
	IsNAT64       bool
}

// GetAPR manages the address pair resolution process
type GetAPR struct {
	mu          sync.Mutex
	sourceAddrs []AddrPair
	addrPairs   []AddrPair
	resolver    string
}

// NewGetAPR creates a new GetAPR instance
func NewGetAPR(iface string) *GetAPR {
	return &GetAPR{
		resolver: getSystemResolver(),
	}
}

// getSystemResolver finds the system DNS resolver
func getSystemResolver() string {
	// This is a simplified version - in production you might want to:
	// 1. Check /etc/resolv.conf on Unix systems
	// 2. Check Windows registry for DNS settings
	// 3. Fall back to well-known public DNS like 8.8.8.8
	return "8.8.8.8" // Using Google DNS as fallback
}

// Enhanced RFC 6724 sorting as per draft-ietf-6man-rfc6724-update
func (g *GetAPR) sortAddrPairs(pairs []AddrPair) []AddrPair {
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]

		// 1. Prefer matching address family
		if a.AddressFamily != b.AddressFamily {
			return a.AddressFamily == 6 // Prefer IPv6
		}

		// 2. Prefer DNSSEC-validated addresses
		if a.DNSSECValid != b.DNSSECValid {
			return a.DNSSECValid
		}

		// 3. Prefer smaller scope
		if a.DestZone != b.DestZone {
			return a.DestZone < b.DestZone
		}

		// 4. Prefer non-NAT64 addresses
		if a.IsNAT64 != b.IsNAT64 {
			return !a.IsNAT64
		}

		// 5. Prefer lower latency (with attempt count weighting)
		weightedLatencyA := a.Latency * time.Duration(a.Attempts+1)
		weightedLatencyB := b.Latency * time.Duration(b.Attempts+1)
		return weightedLatencyA < weightedLatencyB
	})
	return pairs
}

// detectNAT64 checks if NAT64 is available
func (g *GetAPR) detectNAT64() bool {
	// Try to resolve ipv4only.arpa (should return NAT64 address in IPv6-only networks)
	ips, err := net.LookupIP("ipv4only.arpa")
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.To4() == nil && strings.HasPrefix(ip.String(), "64:ff9b::") {
			return true
		}
	}
	return false
}

// resolveWithNAT64 attempts resolution using NAT64
func (g *GetAPR) resolveWithNAT64(host string) ([]net.IP, error) {
	// In a real implementation, you would use the detected NAT64 prefix
	// This is a simplified version that just does normal DNS lookup
	return net.LookupIP(host)
}

// GetAddrPairs gets all valid address pairs with Happy Eyeballs v3 sorting
func (g *GetAPR) GetAddrPairs(host string, port int) []AddrPair {
	var pairs []AddrPair

	// First try regular DNS resolution
	ips, err := net.LookupIP(host)
	if err != nil {
		// Fallback to NAT64 if available
		if g.detectNAT64() {
			if nat64IPs, err := g.resolveWithNAT64(host); err == nil {
				ips = nat64IPs
				for i := range ips {
					ips[i] = net.ParseIP("64:ff9b::" + ips[i].String()) // Simulate NAT64
				}
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Test connections to all addresses
	for _, destIP := range ips {
		af := 4
		if destIP.To4() == nil {
			af = 6
		}

		for _, src := range g.sourceAddrs {
			if src.AddressFamily != af {
				continue // Skip mismatched address families
			}

			ok, latency := g.testConnection(src, destIP, port)
			if ok {
				pair := AddrPair{
					Source:        src.Source,
					SourceZone:    src.SourceZone,
					Dest:          destIP,
					Latency:       latency,
					AddressFamily: af,
					IsNAT64:       strings.HasPrefix(destIP.String(), "64:ff9b::"),
				}
				pairs = append(pairs, pair)
			}
		}
	}

	return g.sortAddrPairs(pairs)
}

// testConnection tests a connection and measures latency
func (g *GetAPR) testConnection(src AddrPair, dest net.IP, port int) (bool, time.Duration) {
	target := net.JoinHostPort(dest.String(), strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout:   DefaultTimeout,
		LocalAddr: &net.TCPAddr{IP: src.Source, Port: 0},
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return false, 0
	}
	conn.Close()
	return true, time.Since(start)
}

// Initialize network interfaces
func (g *GetAPR) Init(port int, verbose bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			af := 4
			if ip.To4() == nil {
				af = 6
			}

			g.sourceAddrs = append(g.sourceAddrs, AddrPair{
				Source:        ip,
				SourceZone:    iface.Name,
				AddressFamily: af,
			})
		}
	}
}

func main() {
	var (
		ifaceName string
		timeout   int
		verbose   bool
		port      int
	)

	flag.StringVar(&ifaceName, "i", "", "Interface to use (short form)")
	flag.IntVar(&timeout, "t", 2, "Timeout in seconds (short form)")
	flag.IntVar(&port, "p", DefaultPort, "Port number (short form, defaults to 80)")
	flag.BoolVar(&verbose, "v", false, "Verbose output (short form)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: getapr [-i interface] [-p port] [-t timeout] [-v] <host>")
		fmt.Println("Example: getapr -i eth0 -p 443 -t 5 -v example.com")
		os.Exit(1)
	}

	host := args[0]
	if port == 0 {
		port = DefaultPort
	}

	apr := NewGetAPR(ifaceName)
	apr.Init(port, verbose)

	pairs := apr.GetAddrPairs(host, port)
	if pairs == nil {
		fmt.Println("Could not resolve any addresses for", host)
		os.Exit(1)
	}

	for _, pair := range pairs {
		flags := ""
		if pair.IsNAT64 {
			flags += "N"
		}
		if flags != "" {
			flags = " [" + flags + "]"
		}

		fmt.Printf("Source: %-15s → Dest: %-15s | Latency: %-8v | Family: IPv%d%s\n",
			pair.Source, pair.Dest, pair.Latency.Round(time.Millisecond), pair.AddressFamily, flags)
	}
}
