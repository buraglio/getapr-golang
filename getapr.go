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

func isDNSSECValidated(host string, resolver string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.SetEdns0(4096, true)

	c := new(dns.Client)
	r, _, err := c.Exchange(m, resolver+":53")
	return err == nil && r.AuthenticatedData
}

func hasSVCBRecords(host string, resolver string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)

	c := new(dns.Client)
	r, _, err := c.Exchange(m, resolver+":53")
	return err == nil && len(r.Answer) > 0
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

func (g *GetAPR) GetAddrPairs(host string, port int) []AddrPair {
	var pairs []AddrPair
	dnssecValid := isDNSSECValidated(host, g.resolver)
	hasSVCB := hasSVCBRecords(host, g.resolver)

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
				pair := AddrPair{
					Source:        src.Source,
					SourceZone:    src.SourceZone,
					Dest:          destIP,
					Latency:       latency,
					AddressFamily: af,
					DNSSECValid:   dnssecValid,
					IsNAT64:       strings.HasPrefix(destIP.String(), "64:ff9b::"),
				}

				if hasSVCB {
					pair.SVCBPriority = 1
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
		ifaceName string
		timeout   int
		verbose   bool
		port      int
		host      string
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
	host = args[0]

	apr := NewGetAPR(ifaceName)
	apr.dnsClient.Timeout = time.Duration(timeout) * time.Second
	apr.Init(port, verbose)

	pairs := apr.GetAddrPairs(host, port)
	if len(pairs) == 0 {
		fmt.Println("No valid address pairs found")
		os.Exit(1)
	}

	fmt.Printf("\n%-15s → %-23s %-8s %-6s %-8s %-7s %s\n",
		"Source", "Destination", "Latency", "Family", "SVCB Pri", "NAT64", "DNSSEC")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println("Note:")
	fmt.Println("- SVCB Pri shown when HTTPS records exist")
	fmt.Println("- NAT64 marked for 64:ff9b:: addresses")
	fmt.Println("- DNSSEC ✓ when validated")
	fmt.Println(strings.Repeat("-", 80))

	for _, pair := range pairs {
		family := fmt.Sprintf("IPv%d", pair.AddressFamily)
		svcbPrio := ""
		if pair.SVCBPriority > 0 {
			svcbPrio = fmt.Sprintf("%d", pair.SVCBPriority)
		}
		nat64 := ""
		if pair.IsNAT64 {
			nat64 = "✓"
		}
		dnssec := ""
		if pair.DNSSECValid {
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
