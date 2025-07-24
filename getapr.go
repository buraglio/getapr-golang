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

	"github.com/miekg/dns"
)

const (
	DefaultPort            = 80
	DefaultTimeout         = 2 * time.Second
	DefaultResolutionDelay = 50 * time.Millisecond
)

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
	SVCBPriority  uint16
	DNSSECValid   bool
	IsNAT64       bool
}

type GetAPR struct {
	mu          sync.Mutex
	sourceAddrs []AddrPair
	addrPairs   []AddrPair
	dnsClient   *dns.Client
	resolver    string
}

func NewGetAPR(iface string) *GetAPR {
	return &GetAPR{
		dnsClient: &dns.Client{
			Timeout: DefaultTimeout,
		},
		resolver: getSystemResolver(),
	}
}

func getSystemResolver() string {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	if config != nil && len(config.Servers) > 0 {
		return config.Servers[0]
	}
	return "8.8.8.8"
}

func (g *GetAPR) sortAddrPairs(pairs []AddrPair) []AddrPair {
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]

		if a.AddressFamily != b.AddressFamily {
			return a.AddressFamily == 6
		}
		if a.SVCBPriority != b.SVCBPriority {
			return a.SVCBPriority < b.SVCBPriority
		}
		if a.DNSSECValid != b.DNSSECValid {
			return a.DNSSECValid
		}
		if a.DestZone != b.DestZone {
			return a.DestZone < b.DestZone
		}
		if a.IsNAT64 != b.IsNAT64 {
			return !a.IsNAT64
		}
		weightedLatencyA := a.Latency * time.Duration(a.Attempts+1)
		weightedLatencyB := b.Latency * time.Duration(b.Attempts+1)
		return weightedLatencyA < weightedLatencyB
	})
	return pairs
}

func (g *GetAPR) detectNAT64() bool {
	m := new(dns.Msg)
	m.SetQuestion("ipv4only.arpa.", dns.TypeAAAA)

	r, _, err := g.dnsClient.Exchange(m, g.resolver+":53")
	if err != nil {
		return false
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.AAAA); ok {
			if strings.HasPrefix(a.AAAA.String(), "64:ff9b::") {
				return true
			}
		}
	}
	return false
}

func (g *GetAPR) resolveWithNAT64(host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)

	r, _, err := g.dnsClient.Exchange(m, g.resolver+":53")
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			nat64IP := net.ParseIP("64:ff9b::" + a.A.String())
			if nat64IP != nil {
				ips = append(ips, nat64IP)
			}
		}
	}
	return ips, nil
}

func (g *GetAPR) checkDNSSEC(host string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.SetEdns0(4096, true)

	r, _, err := g.dnsClient.Exchange(m, g.resolver+":53")
	if err != nil {
		return false
	}
	return r.AuthenticatedData
}

func (g *GetAPR) checkSVCB(host string) ([]AddrPair, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	m.SetEdns0(4096, true)

	r, _, err := g.dnsClient.Exchange(m, g.resolver+":53")
	if err != nil {
		return nil, err
	}

	var results []AddrPair
	for _, ans := range r.Answer {
		if svcb, ok := ans.(*dns.HTTPS); ok {
			ips, _ := net.LookupIP(svcb.Target)
			for _, ip := range ips {
				results = append(results, AddrPair{
					Dest:         ip,
					SVCBPriority: svcb.Priority,
					DNSSECValid:  r.AuthenticatedData,
					AddressFamily: func() int {
						if ip.To4() == nil {
							return 6
						}
						return 4
					}(),
				})
			}
		}
	}
	return results, nil
}

func (g *GetAPR) GetAddrPairs(host string, port int, noNAT64, noDNSSEC, noSVCB bool) []AddrPair {
	var pairs []AddrPair
	var dnssecValid bool
	var svcbPairs []AddrPair
	var err error

	// Check DNSSEC unless disabled
	if !noDNSSEC {
		dnssecValid = g.checkDNSSEC(host)
	}

	// Check SVCB records unless disabled
	if !noSVCB {
		svcbPairs, err = g.checkSVCB(host)
		if err == nil {
			for _, svcbPair := range svcbPairs {
				for _, src := range g.sourceAddrs {
					if src.AddressFamily != svcbPair.AddressFamily {
						continue
					}
					if ok, latency := g.testConnection(src, svcbPair.Dest, port); ok {
						pairs = append(pairs, AddrPair{
							Source:        src.Source,
							SourceZone:    src.SourceZone,
							Dest:          svcbPair.Dest,
							Latency:       latency,
							AddressFamily: svcbPair.AddressFamily,
							SVCBPriority:  svcbPair.SVCBPriority,
							DNSSECValid:   svcbPair.DNSSECValid,
							IsNAT64:       strings.HasPrefix(svcbPair.Dest.String(), "64:ff9b::"),
						})
					}
				}
			}
		}
	}

	// Regular DNS resolution
	ips, err := net.LookupIP(host)
	if err != nil && !noNAT64 {
		if g.detectNAT64() {
			if nat64IPs, err := g.resolveWithNAT64(host); err == nil {
				ips = nat64IPs
			}
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, destIP := range ips {
		af := 4
		if destIP.To4() == nil {
			af = 6
		}

		for _, src := range g.sourceAddrs {
			if src.AddressFamily != af {
				continue
			}

			if ok, latency := g.testConnection(src, destIP, port); ok {
				pair := AddrPair{
					Source:        src.Source,
					SourceZone:    src.SourceZone,
					Dest:          destIP,
					Latency:       latency,
					AddressFamily: af,
					DNSSECValid:   dnssecValid,
					IsNAT64:       !noNAT64 && strings.HasPrefix(destIP.String(), "64:ff9b::"),
				}

				// Only set SVCB priority if we found records and SVCB checking is enabled
				if !noSVCB && len(svcbPairs) > 0 {
					for _, sp := range svcbPairs {
						if sp.Dest.Equal(destIP) {
							pair.SVCBPriority = sp.SVCBPriority
							break
						}
					}
				}

				pairs = append(pairs, pair)
			}
		}
	}

	return g.sortAddrPairs(pairs)
}

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
		ifaceName  string
		timeout    int
		verbose    bool
		port       int
		host       string
		noNAT64    bool
		noDNSSEC   bool
		noSVCB     bool
		disableAll bool
	)

	flag.StringVar(&ifaceName, "i", "", "Network interface to use")
	flag.StringVar(&ifaceName, "interface", "", "Network interface to use")
	flag.IntVar(&timeout, "t", 2, "Timeout in seconds")
	flag.IntVar(&timeout, "timeout", 2, "Timeout in seconds")
	flag.IntVar(&port, "p", DefaultPort, "Port number")
	flag.IntVar(&port, "port", DefaultPort, "Port number")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&noNAT64, "k", false, "Disable NAT64 detection")
	flag.BoolVar(&noDNSSEC, "d", false, "Disable DNSSEC validation")
	flag.BoolVar(&noSVCB, "b", false, "Disable SVCB/HTTPS record checking")
	flag.BoolVar(&disableAll, "x", false, "Disable all special tests (NAT64, DNSSEC, SVCB)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("SA/DA selection and Happy Eyeballs v3 (light) Implementation")
		fmt.Println("Usage: getapr [options] <host>")
		fmt.Println("\nOptions:")
		fmt.Println("  -i, --interface string  Network interface to use")
		fmt.Println("  -t, --timeout int       Timeout in seconds (default 2)")
		fmt.Println("  -p, --port int          Port number (default 80)")
		fmt.Println("  -v, --verbose           Verbose output")
		fmt.Println("  -k                      Disable NAT64 detection")
		fmt.Println("  -d                      Disable DNSSEC validation")
		fmt.Println("  -b                      Disable SVCB/HTTPS record checking")
		fmt.Println("  -x                      Disable all special tests (equivalent to -k -d -b)")
		fmt.Println("\nExamples:")
		fmt.Println("  getapr example.com")
		fmt.Println("  getapr -i eth0 -p 443 -t 5 example.com")
		fmt.Println("  getapr -x example.com (disables all special tests)")
		os.Exit(1)
	}
	host = args[0]

	// If -x is set, override all individual test flags
	if disableAll {
		noNAT64 = true
		noDNSSEC = true
		noSVCB = true
	}

	apr := NewGetAPR(ifaceName)
	apr.dnsClient.Timeout = time.Duration(timeout) * time.Second
	apr.Init(port, verbose)

	pairs := apr.GetAddrPairs(host, port, noNAT64, noDNSSEC, noSVCB)
	if len(pairs) == 0 {
		fmt.Println("No valid address pairs found")
		os.Exit(1)
	}

	// Prepare output. It's not really HEv3, but it kinda respects some aspects
	fmt.Printf("\nSA/DA and Happy Eyeballs v3 (light) Results for %s:%d\n", host, port)
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("%-15s → %-23s %-8s %-6s %-8s %-7s %s\n",
		"Source", "Destination", "Latency", "Family", "SVCB Pri", "NAT64", "DNSSEC")
	fmt.Println(strings.Repeat("-", 80))

	// Show configuration
	fmt.Println("Active Configuration:")
	fmt.Printf("- NAT64 Detection: %v\n", !noNAT64)
	fmt.Printf("- DNSSEC Validation: %v\n", !noDNSSEC)
	fmt.Printf("- SVCB Records: %v\n", !noSVCB)
	fmt.Println(strings.Repeat("-", 80))

	// Print results
	for _, pair := range pairs {
		family := fmt.Sprintf("IPv%d", pair.AddressFamily)
		svcbPrio := ""
		if !noSVCB && pair.SVCBPriority > 0 {
			svcbPrio = fmt.Sprintf("%d", pair.SVCBPriority)
		}
		nat64 := ""
		if !noNAT64 && pair.IsNAT64 {
			nat64 = "✓"
		}
		dnssec := ""
		if !noDNSSEC && pair.DNSSECValid {
			dnssec = "✓"
		}

		fmt.Printf("%-15s → %-23s %-8v %-6s %-8s %-7s %s\n",
			pair.Source,
			pair.Dest,
			pair.Latency.Round(time.Millisecond),
			family,
			svcbPrio,
			nat64,
			dnssec)
	}
}
