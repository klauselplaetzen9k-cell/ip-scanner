# IP Scanner
Advanced network scanner with API enumeration and JSON merging.

## Features

- **Ping sweep** - Check host availability
- **Port scanning** - Find open ports
- **API enumeration** - Call REST APIs on discovered devices
- **Smart JSON merging** - Merge API responses (only overwrite null/0 values)
- **Multiple formats** - JSON, pretty JSON, CSV, text
- **Concurrent scanning** - Fast scanning with async/await

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Scan IP range
```bash
# Single IP
python ip_scanner.py 192.168.1.1

# CIDR range
python ip_scanner.py 192.168.1.0/24

# IP range
python ip_scanner.py 192.168.1.1-10

# Multiple ranges
python ip_scanner.py 192.168.1.0/24 10.0.0.0/24
```

### From file
```bash
python ip_scanner.py -f ips.txt
```

### Output formats
```bash
# JSON
python ip_scanner.py 192.168.1.0/24 -F json

# Pretty JSON
python ip_scanner.py 192.168.1.0/24 -F json-pretty

# CSV
python ip_scanner.py 192.168.1.0/24 -F csv

# Text summary
python ip_scanner.py 192.168.1.0/24 -F text
```

### Output to file
```bash
python ip_scanner.py 192.168.1.0/24 -o results.json
```

## API Integration

The scanner calls APIs on common ports:

| Port | Service | API |
|------|----------|-----|
| 80/443 | Router | System/device info |
| 631 | Printer | Status pages |
| 9100 | Node Exporter | Prometheus metrics |
| 2375/2376 | Docker | Container info |

### JSON Merging

When multiple API endpoints return data, the scanner merges them intelligently:

```python
# Only overwrites null/0/empty values
merged = {
    "hostname": "router1",      # From first API
    "uptime": 86400,           # From second API (preserved)
    "version": "2.1.0",         # From third API
}
```

## Options

```
-t, --timeout     Timeout per host (seconds, default: 5)
-c, --concurrency  Max concurrent scans (default: 100)
-F, --format      Output format (json, json-pretty, text, csv)
-o, --output      Write to file
```

## Examples

### Scan network and save results
```bash
python ip_scanner.py 192.168.1.0/24 -o scan.json
```

### Scan with custom timeout
```bash
python ip_scanner.py 10.0.0.0/24 -t 10 -F json-pretty
```

### From file with parallel scanning
```bash
python ip_scanner.py -f corporate_ips.txt -c 200 -o results/
```

## Programmatic Usage

```python
import asyncio
from ip_scanner import scan_device, parse_ip_range

async def main():
    ips = parse_ip_range("192.168.1.0/24")
    results = await scan_range(ips)
    
    for r in results:
        print(f"{r.ip}: {r.status.value}")
        if r.merged_data:
            print(json.dumps(r.merged_data, indent=2))

asyncio.run(main())
```

## Requirements

- Python 3.8+
- aiohttp
- Other dependencies in requirements.txt

## License

MIT
