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

func (g *GetAPR) querySVCB(host string) ([]AddrPair, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	m.SetEdns0(4096, true) // Enable DNSSEC

	r, _, err := g.dnsClient.Exchange(m, g.resolver+":53")
	if err != nil {
		return nil, err
	}

	var results []AddrPair
	for _, ans := range r.Answer {
		if svcb, ok := ans.(*dns.HTTPS); ok {
			for _, ip := range resolveTarget(svcb.Target) {
				results = append(results, AddrPair{
					Dest:         ip,
					SVCBPriority: svcb.Priority,
					DNSSECValid:  r.AuthenticatedData,
				})
			}
		}
	}
	return results, nil
}

func resolveTarget(target string) []net.IP {
	ips, _ := net.LookupIP(target)
	return ips
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

func (g *GetAPR) GetAddrPairs(host string, port int) []AddrPair {
	var pairs []AddrPair

	// Try SVCB/HTTPS records first
	if svcbPairs, err := g.querySVCB(host); err == nil && len(svcbPairs) > 0 {
		for _, pair := range svcbPairs {
			for _, src := range g.sourceAddrs {
				if ok, latency := g.testConnection(src, pair.Dest, port); ok {
					pair.Source = src.Source
					pair.SourceZone = src.SourceZone
					pair.Latency = latency
					pair.AddressFamily = 6
					pairs = append(pairs, pair)
				}
			}
		}
		if len(pairs) > 0 {
			return g.sortAddrPairs(pairs)
		}
	}

	// Regular DNS resolution
	ips, err := net.LookupIP(host)
	if err != nil && g.detectNAT64() {
		if nat64IPs, err := g.resolveWithNAT64(host); err == nil {
			ips = nat64IPs
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
				pairs = append(pairs, AddrPair{
					Source:        src.Source,
					SourceZone:    src.SourceZone,
					Dest:          destIP,
					Latency:       latency,
					AddressFamily: af,
					IsNAT64:       strings.HasPrefix(destIP.String(), "64:ff9b::"),
				})
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
		ifaceName string
		timeout   int
		verbose   bool
		port      int
	)

	flag.StringVar(&ifaceName, "i", "", "Network interface to use")
	flag.IntVar(&timeout, "t", 2, "Timeout in seconds")
	flag.IntVar(&port, "p", DefaultPort, "Port number")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: getapr [-i interface] [-p port] [-t timeout] [-v] <host>")
		os.Exit(1)
	}

	host := args[0]
	apr := NewGetAPR(ifaceName)
	apr.dnsClient.Timeout = time.Duration(timeout) * time.Second
	apr.Init(port, verbose)

	pairs := apr.GetAddrPairs(host, port)
	for _, pair := range pairs {
		flags := ""
		if pair.DNSSECValid {
			flags += "D"
		}
		if pair.IsNAT64 {
			flags += "N"
		}
		if pair.SVCBPriority > 0 {
			flags += fmt.Sprintf("P%d", pair.SVCBPriority)
		}
		if flags != "" {
			flags = " [" + flags + "]"
		}

		fmt.Printf("%-15s → %-15s | %-8v | IPv%d%s\n",
			pair.Source, pair.Dest, pair.Latency.Round(time.Millisecond),
			pair.AddressFamily, flags)
	}
}
