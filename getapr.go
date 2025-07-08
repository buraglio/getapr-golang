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

type AddrPair struct {
	Source      net.IP
	SourceZone  string
	Dest        net.IP
	DestZone    string
	Latency     time.Duration
	ScopeID     int
	SameNetwork bool
}

type GetAPR struct {
	mu           sync.Mutex
	sourceAddrs  []AddrPair
	destAddrs    []AddrPair
	addrPairs    []AddrPair
	pollCount    int
	maxDestAddrs int
	initialized  bool
	timeout      time.Duration
	ulaPresent   bool
	rfc1918      bool
	targetIface  string
}

func NewGetAPR(iface string) *GetAPR {
	return &GetAPR{
		maxDestAddrs: 10,
		timeout:      2 * time.Second,
		targetIface:  iface,
	}
}

func isULA(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return false
	}
	return ip[0] == 0xfd || ip[0] == 0xfc
}

func isPrivateIPv4(ip net.IP) bool {
	if len(ip) != net.IPv4len {
		return false
	}
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

func parseZone(ipStr string) (net.IP, string) {
	if idx := strings.LastIndex(ipStr, "%"); idx != -1 {
		ip := net.ParseIP(ipStr[:idx])
		return ip, ipStr[idx+1:]
	}
	return net.ParseIP(ipStr), ""
}

func (g *GetAPR) UpdateSources() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.sourceAddrs = []AddrPair{}
	iface, err := net.InterfaceByName(g.targetIface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %v", g.targetIface, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface %s: %v", g.targetIface, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}

		zone := ""
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			zone = iface.Name
		}

		if ip.To4() == nil && isULA(ip) {
			g.ulaPresent = true
		} else if ip.To4() != nil && isPrivateIPv4(ip) {
			g.rfc1918 = true
		}

		g.sourceAddrs = append(g.sourceAddrs, AddrPair{
			Source:     ip,
			SourceZone: zone,
		})
	}

	if len(g.sourceAddrs) == 0 {
		return fmt.Errorf("no valid addresses found on interface %s", g.targetIface)
	}

	return nil
}

func (g *GetAPR) testConnection(src AddrPair, dst AddrPair, port int) (bool, time.Duration) {
	if src.Source.IsLinkLocalUnicast() {
		if !dst.Source.IsLinkLocalUnicast() || src.SourceZone != dst.SourceZone {
			return false, 0
		}
	}

	dstAddr := dst.Source.String()
	if dst.Source.IsLinkLocalUnicast() && dst.SourceZone != "" {
		dstAddr += "%" + dst.SourceZone
	}

	dialer := &net.Dialer{
		Timeout:   g.timeout,
		LocalAddr: &net.TCPAddr{IP: src.Source, Zone: src.SourceZone},
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", net.JoinHostPort(dstAddr, strconv.Itoa(port)))
	if err != nil {
		return false, 0
	}
	defer conn.Close()

	_, err = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	if err != nil {
		return false, 0
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		return false, 0
	}

	return true, time.Since(start)
}

func (g *GetAPR) validAddressPair(src, dst AddrPair) bool {
	if src.Source.IsLinkLocalUnicast() {
		return dst.Source.IsLinkLocalUnicast() && src.SourceZone == dst.SourceZone
	}
	if dst.Source.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func (g *GetAPR) poll(port int) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		g.mu.Lock()
		srcs := make([]AddrPair, len(g.sourceAddrs))
		copy(srcs, g.sourceAddrs)
		dests := make([]AddrPair, len(g.destAddrs))
		copy(dests, g.destAddrs)
		g.mu.Unlock()

		for _, src := range srcs {
			var removeDests []AddrPair
			for _, dst := range dests {
				if !g.validAddressPair(src, dst) {
					continue
				}

				ok, latency := g.testConnection(src, dst, port)
				g.mu.Lock()
				if ok {
					found := false
					for i, pair := range g.addrPairs {
						if pair.Source.Equal(src.Source) && pair.Dest.Equal(dst.Source) {
							g.addrPairs[i].Latency = latency
							found = true
							break
						}
					}
					if !found {
						g.addrPairs = append(g.addrPairs, AddrPair{
							Source:      src.Source,
							SourceZone:  src.SourceZone,
							Dest:        dst.Source,
							DestZone:    dst.SourceZone,
							Latency:     latency,
							SameNetwork: src.SourceZone == dst.SourceZone,
						})
					}
				} else {
					removeDests = append(removeDests, dst)
				}
				g.mu.Unlock()
			}

			if len(removeDests) > 0 {
				g.mu.Lock()
				var newDests []AddrPair
				for _, d := range g.destAddrs {
					keep := true
					for _, rd := range removeDests {
						if d.Source.Equal(rd.Source) {
							keep = false
							break
						}
					}
					if keep {
						newDests = append(newDests, d)
					}
				}
				g.destAddrs = newDests
				g.mu.Unlock()
			}
		}

		g.pollCount++
		if g.pollCount > 1000 {
			g.pollCount = 0
		}
	}
}

func (g *GetAPR) Init(port int, verbose bool) {
	if g.initialized {
		return
	}

	if err := g.UpdateSources(); err != nil {
		if verbose {
			fmt.Printf("Warning: %v\n", err)
		}
		return
	}

	go g.poll(port)
	g.initialized = true

	if verbose {
		fmt.Printf("Initialized with interface %s addresses:\n", g.targetIface)
		for _, addr := range g.sourceAddrs {
			addrType := "Global"
			if addr.Source.IsLinkLocalUnicast() {
				addrType = "Link-Local"
			} else if isULA(addr.Source) {
				addrType = "ULA"
			} else if addr.Source.To4() != nil && isPrivateIPv4(addr.Source) {
				addrType = "RFC1918"
			}
			fmt.Printf("- %s (Type: %s, Zone: %s)\n", addr.Source, addrType, addr.SourceZone)
		}
	}
}

func (g *GetAPR) GetAddrPairs(host string, port int) []AddrPair {
	if !g.initialized {
		g.Init(port, false)
	}

	var pairs []AddrPair
	rawAddrs, err := net.LookupIP(host)
	if err != nil {
		return pairs
	}

	var destAddrs []AddrPair
	for _, addr := range rawAddrs {
		destAddrs = append(destAddrs, AddrPair{
			Source:     addr,
			SourceZone: "",
		})
	}

	sort.Slice(destAddrs, func(i, j int) bool {
		return len(destAddrs[i].Source) == net.IPv6len && len(destAddrs[j].Source) != net.IPv6len
	})

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, dst := range destAddrs {
		for _, src := range g.sourceAddrs {
			if !g.validAddressPair(src, dst) {
				continue
			}

			ok, latency := g.testConnection(src, dst, port)
			if ok {
				pairs = append(pairs, AddrPair{
					Source:      src.Source,
					SourceZone:  src.SourceZone,
					Dest:        dst.Source,
					DestZone:    dst.SourceZone,
					Latency:     latency,
					SameNetwork: src.SourceZone == dst.SourceZone,
				})
			}
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].SameNetwork && !pairs[j].SameNetwork {
			return true
		}
		if !pairs[i].SameNetwork && pairs[j].SameNetwork {
			return false
		}
		if len(pairs[i].Source) == net.IPv6len && len(pairs[j].Source) != net.IPv6len {
			return true
		}
		if len(pairs[i].Source) != net.IPv6len && len(pairs[j].Source) == net.IPv6len {
			return false
		}
		return pairs[i].Latency < pairs[j].Latency
	})

	return pairs
}

func (g *GetAPR) Status() map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]bool{
		"ULA_present": g.ulaPresent,
		"RFC1918":     g.rfc1918,
	}
}

func printHelp() {
	fmt.Println("Usage: getapr -i <interface> [options] <host>")
	fmt.Println("Required flags:")
	fmt.Println("  -i, --interface  Network interface to use")
	fmt.Println("Options:")
	fmt.Println("  -h, --help       Show this help message")
	fmt.Println("  -p, --port       Port number (default: 80)")
	fmt.Println("  -t, --timeout    Timeout in seconds (default: 2)")
	fmt.Println("  -v, --verbose    Verbose output")
}

func main() {
	var (
		help      bool
		port      int
		timeout   int
		verbose   bool
		ifaceName string
	)

	flag.BoolVar(&help, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.IntVar(&port, "p", 80, "Port number")
	flag.IntVar(&port, "port", 80, "Port number")
	flag.IntVar(&timeout, "t", 2, "Timeout in seconds")
	flag.IntVar(&timeout, "timeout", 2, "Timeout in seconds")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.StringVar(&ifaceName, "i", "", "Network interface to use (required)")
	flag.StringVar(&ifaceName, "interface", "", "Network interface to use (required)")
	flag.Parse()

	if help {
		printHelp()
		os.Exit(0)
	}

	if ifaceName == "" {
		fmt.Println("Error: interface flag is required")
		printHelp()
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 1 {
		printHelp()
		os.Exit(1)
	}

	host := args[0]
	apr := NewGetAPR(ifaceName)
	apr.timeout = time.Duration(timeout) * time.Second
	apr.Init(port, verbose)

	pairs := apr.GetAddrPairs(host, port)
	for _, pair := range pairs {
		zoneInfo := ""
		if pair.SourceZone != "" || pair.DestZone != "" {
			zoneInfo = fmt.Sprintf(" (Source Zone: %s, Dest Zone: %s)", pair.SourceZone, pair.DestZone)
		}
		fmt.Printf("Source: %s → Dest: %s | Latency: %v%s\n",
			pair.Source, pair.Dest, pair.Latency.Round(time.Millisecond), zoneInfo)
	}

	if verbose {
		status := apr.Status()
		fmt.Printf("Status: %+v\n", status)
	}
}
