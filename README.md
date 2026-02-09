# Advanced IP Scanner

Network discovery with custom API endpoints and session/cookie handling.

## Features

- **IP Input**: CIDR ranges, individual IPs, or file input
- **Custom Endpoints**: Define your own API endpoints in JSON
- **Session Preservation**: Cookies/auth maintained across requests
- **Ordered Scanning**: Endpoints scanned in defined order
- **Nmap Integration**: Service detection and port scanning
- **Smart Merging**: Combine responses intelligently
- **Multiple Formats**: JSON, pretty JSON, CSV, text

## Usage

### Basic Scan
```bash
python ip_scanner.py 192.168.1.0/24
```

### Auto-Detect Local Subnet
Automatically detect your local IP and scan the subnet (.100-.150):
```bash
python ip_scanner.py --auto-subnet
```

### Custom Endpoints
```bash
python ip_scanner.py 192.168.1.1 -e endpoints.json -o results.json
```

### Combine Options
```bash
python ip_scanner.py --auto-subnet -e endpoints.json -o results.json
```

### Nmap Integration
Run nmap service detection on discovered hosts:
```bash
# Basic nmap scan
python ip_scanner.py 192.168.1.0/24 --nmap

# Scan specific ports
python ip_scanner.py 192.168.1.0/24 --nmap --nmap-ports "80,443,22,8080"

# Custom nmap arguments
python ip_scanner.py 192.168.1.0/24 --nmap --nmap-args "-sV -sC -p-"

# Combine with endpoints
python ip_scanner.py --auto-subnet --nmap -e endpoints.json -o results.json
```

## Endpoint Configuration

Define custom endpoints in JSON:

```json
{
  "groups": [
    {
      "name": "api_group",
      "endpoints": [
        {
          "path": "/api/login",
          "method": "POST",
          "body": "{\"username\": \"admin\"}",
          "preserve_session": true,
          "merge_strategy": "smart"
        },
        {
          "path": "/api/protected/resource",
          "method": "GET"
        }
      ]
    }
  ]

```

### Options

| Option | Description |
|--------|-------------|
| `--auto-subnet` | Auto-detect local IP and scan .100-.150 |
| `--nmap` | Run nmap scan on discovered hosts |
| `--nmap-ports` | Ports to scan with nmap |
| `--nmap-args` | Nmap arguments (default: -sV -sC --open) |
| `-f, --file` | IP list file |
| `-e, --endpoints` | Endpoint definitions JSON |
| `-o, --output` | Output file |
| `-F, --format` | json/json-pretty/text/csv |
| `-t, --timeout` | Request timeout |
| `-c, --concurrent` | Max concurrent scans |

## Auto-Subnet Detection

The `--auto-subnet` flag detects your machine's local IP and automatically scans a typical device range:

```
192.168.8.15 -> scans 192.168.8.100-150
```

Useful for quickly discovering devices on your local network.

## Session Handling

Set `preserve_session: true` to maintain cookies across requests for authenticated sessions.

## Nmap Service Detection

When `--nmap` is enabled, the scanner runs nmap on discovered hosts for comprehensive port and service detection:

- **Service Version Detection**: `-sV` identifies service versions
- **Default Scripts**: `-sC` runs default NSE scripts
- **Open Ports Only**: `--open` filters to open ports

Results are merged into the output under `endpoint_results.nmap`.

## Output Format

Results are organized with IP addresses as dictionary keys:

```json
{
  "192.168.1.1": {
    "hostname": "router.local",
    "status": "online",
    "ping_time_ms": 1.5,
    "endpoint_results": {
      "nmap": {
        "ports": [
          "22/tcp   open  ssh     OpenSSH 8.2",
          "80/tcp   open  http    nginx 1.18.0"
        ]
      }
    },
    "merged_data": {
      "version": "2.1.0",
      "uptime": 86400
    },
    "error": null,
    "scan_time_ms": 1523.4
  },
  "192.168.1.2": {
    "hostname": null,
    "status": "offline",
    "ping_time_ms": null,
    "endpoint_results": {},
    "merged_data": {},
    "error": null,
    "scan_time_ms": 45.2
  }
}
```
