# Advanced IP Scanner

Network discovery with custom API endpoints and session/cookie handling.

## Features

- **IP Input**: CIDR ranges, individual IPs, or file input
- **Custom Endpoints**: Define your own API endpoints in JSON
- **Session Preservation**: Cookies/auth maintained across requests
- **Ordered Scanning**: Endpoints scanned in defined order
- **Smart Merging**: Combine responses intelligently
- **Multiple Formats**: JSON, pretty JSON, CSV, text

## Usage

### Basic Scan
```bash
python ip_scanner.py 192.168.1.0/24
```

### Custom Endpoints
```bash
python ip_scanner.py 192.168.1.1 -e endpoints.json -o results.json
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
| `-f, --file` | IP list file |
| `-e, --endpoints` | Endpoint definitions JSON |
| `-o, --output` | Output file |
| `-F, --format` | json/json-pretty/text/csv |
| `-t, --timeout` | Request timeout |
| `-c, --concurrent` | Max concurrent scans |

## Session Handling

Set `preserve_session: true` to maintain cookies across requests for authenticated sessions.
