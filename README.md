Markdown
# GetAPR - Advanced Path Reporter

A Go implementation of network path analysis tool that tests connectivity between source and destination addresses with strict interface binding and IPv6 zone awareness. Like its progenitor, its intention is to provide address pairs with latency details that can be used to determine the best possible pair of addresses. Instead of returning a list of destination addresses, it returns a list of source and destination address pairs, ranked based on latency and [rfc6724-update](https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/). In theory, this mitigates the problem of the operating system choosing an inappropriate source address and lays a foundation of being able to choose other criteria for SA/DA pairing.
Nevertheless, upper layer code needs to cycle through the list of address pairs until it makes a successful connection. There is definitely a lot of room for improvement, but the foundation is at least a working example of another option for SA/DA pairing. 

## Features

- Interface-specific testing (bound to specified network interface)
- IPv6 zone/scope ID awareness
- Link-local address restriction enforcement
- Accurate latency measurements
- Support for both IPv4 and IPv6, with support for ranking based on [rfc6724-update](https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/)
- Verbose output mode
- Configurable timeout and port settings
- Functionality more closely resembling [Happy Eyeballs v3](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/)
- Proper DNSSEC validation
- Proper query and ranking based on HTTPS/SVCB records
- Simple detection of NAT64 in the path (uses simple detection method based on ipv4only.arpa and 64::)
- "Pretty" formatting output with human readable table

## Installation

```
git clone https://github.com/buraglio/getapr-golang.git
cd getapr
go mod init
go get github.com/miekg/dns
go build -o getapr
```

## Usage

`./getapr -i interface [options] host`


### Required Flags

```
Flag	Description
-i, --interface	Network interface to use (e.g., eth0, en0, wlan0)
```

### Options

```
Flag	Description	Default
-p, --port	Port number to test	(default: 80)
-t, --timeout	Timeout in seconds	(default: 2)
-v, --verbose	Enable verbose output	(default: false)
-k disable NAT64 detection (default: false)
-d disable DNSSEC validation (default: false)
-b disable SVCB/HTTPS record checking (default: false)
-x disable all three tests (default: false)
-h, --help	Show help message	

```

## Examples

### Basic usage
`./getapr -i en0 -p 443 -t 1 -v ipv6.army`

### Test HTTPS connectivity with verbose output
`./getapr -i en0 -p 443 -t 1 -v ipv6.army`

### Custom timeout of 5 seconds

`./getapr -i en0 -p 443 -t 5 -v ipv6.army`

### Output Format
The program outputs connection pairs in the following format:

```
Source          → Destination             Latency  Family SVCB Pri NAT64   DNSSEC
```

### Example:

```
Source          → Destination             Latency  Family SVCB Pri NAT64   DNSSEC
--------------------------------------------------------------------------------
Note:
- SVCB Pri shown when HTTPS records exist
- NAT64 marked for 64:ff9b:: addresses
- DNSSEC ✓ when validated
--------------------------------------------------------------------------------
3fff:c0ff:ee:8f01:1cff:70b9:6db0:2812 → 2600:1f18:16e:df01::258 29ms     IPv6   1                ✓
3fff:c0ff:ee:8f01:60ee:d8b8:8f01:f05e → 2600:1f18:16e:df01::258 30ms     IPv6   1                ✓
3fff:c0ff:ee:8f01:60ee:d8b8:8f01:f05e → 2600:1f18:16e:df01::259 32ms     IPv6   1                ✓
3fff:c0ff:ee:8f01:1cff:70b9:6db0:2812 → 2600:1f18:16e:df01::259 47ms     IPv6   1                ✓
10.9.40.9      → 18.208.88.157           31ms     IPv4   1                ✓
10.9.40.9      → 98.84.224.111           32ms     IPv4   1                ✓
```

### IPv6 Zone Handling

The tool strictly enforces IPv6 zone/scope rules:
- Link-local addresses can only communicate with other link-local addresses in the same zone
- IPv6 zone identifiers are preserved and displayed in results
- Link-local addresses never attempt to reach global addresses

## Requirements
Go 1.16 or later
Linux/macOS/Unix (Windows support untested)
Root privileges may be required for certain interface operations

## Limitations and Known issues

Currently only tests TCP connectivity

Doesn't support multiple simultaneous interface testing (by design, the first version did and it was an absolute mess)

Windows support hasn't been tested, but it should compile

It's probably buggy and sub-optimal in many, many ways

Adding HE3 support made this fairly sluggish. It's almost certainly because of how it is implemented, and it could absolutely use someone with actual skill to
take a look and fix it.

## Contributing
Pull requests and issues are welcome, but probably open up an issue first - let's discuss it. Please ensure:
- Code follows existing style or improves it.
- New features include tests
- Documentation is updated

Note: This tool was originally ported from a [Python implementation](https://github.com/becarpenter/getapr) to Go, see `attic`.
