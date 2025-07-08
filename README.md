Markdown
# GetAPR - Advanced Path Reporter

A Go implementation of network path analysis tool that tests connectivity between source and destination addresses with strict interface binding and IPv6 zone awareness.

## Features

- Interface-specific testing (bound to specified network interface)
- IPv6 zone/scope ID awareness
- Link-local address restriction enforcement
- Accurate latency measurements
- Support for both IPv4 and IPv6
- Verbose output mode
- Configurable timeout and port settings

## Installation

```
git clone https://github.com/buraglio/getapr-golang.git
cd getapr
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
-p, --port	Port number to test	80
-t, --timeout	Timeout in seconds	2
-v, --verbose	Enable verbose output	false
-h, --help	Show help message	
```


## Examples

### Basic usage
`./getapr -i eth0 www.ietf.org`

### Test HTTPS connectivity with verbose output
`./getapr -i en0 -p 443 -v example.com`

### Custom timeout of 5 seconds

`./getapr -i wlan0 -t 5 google.com`

### Output Format
The program outputs connection pairs in the following format:

Text Only
Source: source_ip → Dest: dest_ip | Latency: duration [Zone info]

### Example:

Text Only
```
Source: 192.168.1.100 → Dest: 93.184.216.34 | Latency: 23.456ms
Source: fe80::1%eth0 → Dest: fe80::2%eth0 | Latency: 1.234ms (Source Zone: eth0, Dest Zone: eth0)
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

## Limitations

Currently only tests TCP connectivity

Doesn't support multiple simultaneous interface testing

Windows support hasn't been thoroughly tested, but it should compile

It's probably buggy and sub-optimal in many, many ways

## Contributing
Pull requests and issues are welcome, but probably open up an issue first - let's discuss it. Please ensure:
- Code follows existing style or improves it.
- New features include tests
- Documentation is updated

Note: This tool was originally ported from a Python implementation to Go, see `attic`.
