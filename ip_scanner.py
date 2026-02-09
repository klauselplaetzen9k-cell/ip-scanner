"""
Advanced IP Scanner CLI - Network discovery and API enumeration tool.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import NamedTuple, Optional
from enum import Enum
import argparse
import json
import asyncio
import aiohttp
import socket
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod
from datetime import datetime
from urllib.parse import urljoin
import sys
from pathlib import Path


class OutputFormat(Enum):
    """Output format options."""
    JSON = "json"
    JSON_PRETTY = "json-pretty"
    TEXT = "text"
    CSV = "csv"


class ScanStatus(Enum):
    """Device scan status."""
    PINGABLE = "pingable"
    ONLINE = "online"
    OFFLINE = "offline"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ScanResult:
    """Result of scanning a single device."""
    ip: str
    hostname: Optional[str] = None
    status: ScanStatus = ScanStatus.OFFLINE
    ping_time_ms: Optional[float] = None
    apis: dict[str, dict] = field(default_factory=dict)
    merged_data: dict = field(default_factory=dict)
    error: Optional[str] = None
    scan_time_ms: float = 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "status": self.status.value,
            "ping_time_ms": self.ping_time_ms,
            "apis": self.apis,
            "merged_data": self.merged_data,
            "error": self.error,
            "scan_time_ms": self.scan_time_ms,
        }


class APIEndpoint(NamedTuple):
    """API endpoint definition."""
    path: str
    method: str = "GET"
    timeout: float = 5.0
    expected_fields: list[str] = []


class BaseAPIClient(ABC):
    """Base class for API clients."""
    
    ENDPOINTS: list[APIEndpoint] = []
    
    def __init__(self, ip: str, timeout: float = 5.0):
        self.ip = ip
        self.timeout = timeout
        self.base_url = f"http://{ip}"
    
    @abstractmethod
    async def scan(self, session: aiohttp.ClientSession) -> dict:
        """Scan device and return merged API data."""
        pass
    
    def merge_data(self, *responses: dict) -> dict:
        """Merge multiple API responses.
        
        Only overwrite values that are null/0/empty.
        Preserve existing non-null values.
        """
        merged: dict = {}
        
        for response in responses:
            if not response:
                continue
            
            for key, value in response.items():
                if key not in merged:
                    merged[key] = value
                elif self._should_overwrite(merged[key]):
                    merged[key] = value
        
        return merged
    
    def _should_overwrite(self, value: any) -> bool:
        """Check if value should be overwritten."""
        if value is None:
            return True
        if isinstance(value, (int, float)) and value == 0:
            return True
        if isinstance(value, str) and value == "":
            return True
        if isinstance(value, list) and len(value) == 0:
            return True
        return False


class RouterAPI(BaseAPIClient):
    """Generic router/switch API client."""
    
    ENDPOINTS = [
        APIEndpoint("/api/system/info"),
        APIEndpoint("/api/device/info"),
        APIEndpoint("/api/network/status"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession) -> dict:
        """Scan device using router APIs."""
        results = []
        
        for endpoint in self.ENDPOINTS:
            try:
                async with session.get(
                    urljoin(self.base_url, endpoint.path),
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(data)
            except Exception:
                continue
        
        return self.merge_data(*results) if results else {}


class PrinterAPI(BaseAPIClient):
    """Network printer API client."""
    
    ENDPOINTS = [
        APIEndpoint("/ipp/print"),
        APIEndpoint("/api/status"),
        APIEndpoint("/network.json"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession) -> dict:
        """Scan device using printer APIs."""
        results = []
        
        for endpoint in self.ENDPOINTS:
            try:
                async with session.get(
                    urljoin(self.base_url, endpoint.path),
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(data)
            except Exception:
                continue
        
        return self.merge_data(*results) if results else {}


class DockerAPI(BaseAPIClient):
    """Docker API client."""
    
    ENDPOINTS = [
        APIEndpoint("/info"),
        APIEndpoint("/containers/json"),
    ]
    
    ENDPOINTS = [
        APIEndpoint("/v1.45/info"),
        APIEndpoint("/v1.45/containers/json"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession) -> dict:
        """Scan device using Docker API."""
        results = []
        
        for endpoint in self.ENDPOINTS:
            try:
                async with session.get(
                    f"http://{self.ip}:2375{endpoint.path}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(data)
            except Exception:
                continue
        
        return self.merge_data(*results) if results else {}


class NodeExporterAPI(BaseAPIClient):
    """Prometheus Node Exporter API client."""
    
    ENDPOINTS = [
        APIEndpoint("/api/v1/query?query=up"),
        APIEndpoint("/metrics"),
    ]
    
    async def scan(self, session: aiohttp.ClientSession) -> dict:
        """Scan device using Node Exporter metrics."""
        results = []
        
        try:
            async with session.get(
                f"http://{self.ip}:9100{self.ENDPOINTS[0].path}",
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results.append(data)
        except Exception:
            pass
        
        return self.merge_data(*results) if results else {}


class APIRegistry:
    """Registry of known API clients by port/service."""
    
    CLIENTS = {
        80: RouterAPI,
        443: RouterAPI,
        631: PrinterAPI,
        9100: NodeExporterAPI,
        2375: DockerAPI,
        2376: DockerAPI,
    }
    
    @classmethod
    def get_client(self, port: int) -> type[BaseAPIClient] | None:
        """Get API client class for port."""
        return self.CLIENTS.get(port)
    
    @classmethod
    def get_ports(self) -> list[int]:
        """Get all known ports."""
        return list(self.CLIENTS.keys())


def ping_host(ip: str, count: int = 1, timeout: float = 2.0) -> tuple[bool, float]:
    """
    Ping a host and return (success, time_ms).
    
    Cross-platform ping implementation.
    """
    try:
        # Try system ping first (more accurate)
        if sys.platform.startswith("linux"):
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(int(timeout)), ip],
                capture_output=True,
                timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                # Parse ping time
                match = re.search(r"time=([\d.]+)", result.stdout.decode())
                if match:
                    return True, float(match.group(1))
                return True, 0.0
        elif sys.platform == "darwin":
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), ip],
                capture_output=True,
                timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                return True, 0.0
        else:
            # Windows
            result = subprocess.run(
                ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip],
                capture_output=True,
                timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                return True, 0.0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return False, 0.0


def get_hostname(ip: str) -> Optional[str]:
    """Reverse DNS lookup for hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


async def scan_device(
    ip: str,
    open_ports: list[int] = None,
    timeout: float = 5.0,
) -> ScanResult:
    """Scan a single device."""
    import aiohttp
    
    start_time = datetime.utcnow()
    result = ScanResult(ip=ip)
    
    # Ping check
    pingable, ping_time = ping_host(ip)
    result.ping_time_ms = ping_time
    
    if not pingable:
        result.status = ScanStatus.OFFLINE
        result.scan_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        return result
    
    result.status = ScanStatus.PINGABLE
    
    # Get hostname
    result.hostname = get_hostname(ip)
    
    # Scan open ports and call APIs
    if not open_ports:
        open_ports = await scan_ports(ip, timeout)
    
    # Call APIs on found ports
    async with aiohttp.ClientSession() as session:
        for port in open_ports:
            client_class = APIRegistry.get_client(port)
            if client_class:
                try:
                    client = client_class(ip, timeout)
                    api_data = await client.scan(session)
                    if api_data:
                        result.apis[f"port_{port}"] = api_data
                        result.merged_data = client.merge_data(
                            result.merged_data, api_data
                        )
                        result.status = ScanStatus.ONLINE
                except Exception as e:
                    result.error = str(e)
    
    result.scan_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
    return result


async def scan_ports(ip: str, timeout: float = 5.0) -> list[int]:
    """Quick port scan to find open ports."""
    common_ports = [80, 443, 22, 8080, 8443, 2375, 2376, 9100]
    open_ports = []
    
    async with asyncio.timeout(timeout):
        tasks = []
        for port in common_ports:
            task = asyncio.create_task(check_port(ip, port, timeout))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, is_open in zip(common_ports, results):
            if is_open:
                open_ports.append(port)
    
    return open_ports


async def check_port(ip: str, port: int, timeout: float) -> bool:
    """Check if port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        await asyncio.sleep(0)
        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_connect(sock, (ip, port)),
                timeout=timeout
            )
            return True
        except (asyncio.TimeoutError, OSError):
            return False
        finally:
            sock.close()
    except Exception:
        return False


def parse_ip_range(range_str: str) -> list[str]:
    """Parse IP range string to list of IPs."""
    ips = []
    
    # CIDR notation: 192.168.1.0/24
    if "/" in range_str:
        import ipaddress
        network = ipaddress.ip_network(range_str, strict=False)
        for ip in network:
            if not ip.is_reserved:
                ips.append(str(ip))
        return ips
    
    # Range: 192.168.1.1-10
    if "-" in range_str:
        parts = range_str.rsplit("-", 1)
        if len(parts) == 2:
            base = parts[0].rsplit(".", 3)
            if len(base) == 4:
                prefix = ".".join(base[:3]) + "."
                start, end = int(base[3]), int(parts[1])
                for i in range(start, end + 1):
                    ips.append(f"{prefix}{i}")
                return ips
    
    # Single IP or hostname
    return [range_str]


def load_ips_from_file(path: str) -> list[str]:
    """Load IPs from file (one per line or comma-separated)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"IP file not found: {path}")
    
    content = path.read_text()
    # Support multiple formats
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle comma/space separated
        for ip in re.split(r"[,\s]+", line):
            if ip:
                ips.append(ip)
    
    return ips


async def scan_range(
    ips: list[str],
    output_format: OutputFormat = OutputFormat.JSON_PRETTY,
    output_file: str = None,
    timeout: float = 5.0,
    max_concurrent: int = 100,
) -> list[ScanResult]:
    """Scan multiple IPs concurrently."""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_limit(ip: str) -> ScanResult:
        async with semaphore:
            return await scan_device(ip, timeout=timeout)
    
    tasks = [scan_with_limit(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    
    return list(results)


def format_output(
    results: list[ScanResult],
    format: OutputFormat,
) -> str:
    """Format scan results for output."""
    if format == OutputFormat.JSON:
        return json.dumps([r.to_dict() for r in results])
    elif format == OutputFormat.JSON_PRETTY:
        return json.dumps(
            [r.to_dict() for r in results],
            indent=2
        )
    elif format == OutputFormat.CSV:
        lines = ["ip,hostname,status,ping_ms,scan_time_ms"]
        for r in results:
            lines.append(
                f"{r.ip},{r.hostname or ''},{r.status.value},"
                f"{r.ping_time_ms or ''},{r.scan_time_ms:.1f}"
            )
        return "\n".join(lines)
    else:
        # Text format
        lines = [f"Scanned {len(results)} devices:\n"]
        for r in results:
            status_icon = "✓" if r.status == ScanStatus.PINGABLE else "✗"
            lines.append(
                f"{status_icon} {r.ip}"
                + (f" ({r.hostname})" if r.hostname else "")
                + f" - {r.status.value}"
                + (f" {r.ping_time_ms:.1f}ms" if r.ping_time_ms else "")
            )
            for path, data in r.apis.items():
                lines.append(f"  └── {path}: {len(data)} fields")
        return "\n".join(lines)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced IP Scanner with API enumeration"
    )
    
    parser.add_argument(
        "ips",
        nargs="*",
        help="IP addresses or ranges to scan (CIDR or start-end)"
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing IPs (one per line or comma-separated)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path"
    )
    parser.add_argument(
        "-F", "--format",
        choices=["json", "json-pretty", "text", "csv"],
        default="json-pretty",
        help="Output format (default: json-pretty)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Timeout per host in seconds (default: 5)"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=100,
        help="Max concurrent scans (default: 100)"
    )
    
    args = parser.parse_args()
    
    # Collect IPs
    ips = []
    
    if args.file:
        try:
            ips.extend(load_ips_from_file(args.file))
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    for ip_range in args.ips:
        ips.extend(parse_ip_range(ip_range)
    
    if not ips:
        print("Error: No IPs specified", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    # Remove duplicates
    ips = list(dict.fromkeys(ips))
    
    print(f"Scanning {len(ips)} targets...")
    
    # Run scan
    results = asyncio.run(scan_range(
        ips,
        timeout=args.timeout,
        max_concurrent=args.concurrency,
    ))
    
    # Output
    output = format_output(
        results,
        OutputFormat(args.format)
    )
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Results written to {args.output}")
    else:
        print(output)
    
    # Exit with count of online devices
    online = sum(1 for r in results if r.status == ScanStatus.ONLINE)
    sys.exit(0 if online > 0 else 1)


if __name__ == "__main__":
    main()


def merge_json(responses: list[dict]) -> dict:
    """Merge multiple JSON responses.
    
    Only overwrite values that are null/0/empty.
    Preserve existing non-null values.
    """
    merged: dict = {}
    
    for response in responses:
        if not response:
            continue
            
        for key, value in response.items():
            if key not in merged:
                merged[key] = value
            elif merged[key] is None or merged[key] == 0 or merged[key] == "":
                merged[key] = value
            elif isinstance(merged[key], list) and len(merged[key]) == 0:
                merged[key] = value
            elif isinstance(merged.get(key), dict) and isinstance(value, dict):
                merged[key] = {**value, **merged[key]}
    
    return merged
