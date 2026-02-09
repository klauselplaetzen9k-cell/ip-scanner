"""
Advanced IP Scanner CLI - Network discovery with custom endpoints.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin


class OutputFormat(Enum):
    JSON = "json"
    JSON_PRETTY = "json-pretty"
    TEXT = "text"
    CSV = "csv"


class ScanStatus(Enum):
    PINGABLE = "pingable"
    ONLINE = "online"
    OFFLINE = "offline"
    TIMEOUT = "timeout"
    ERROR = "error"


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


@dataclass
class APIEndpoint:
    path: str
    method: HTTPMethod = HTTPMethod.GET
    timeout: float = 5.0
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    preserve_session: bool = False
    merge_strategy: str = "smart"


@dataclass
class EndpointGroup:
    name: str
    endpoints: list[APIEndpoint]


@dataclass
class ScanResult:
    ip: str
    hostname: Optional[str] = None
    status: ScanStatus = ScanStatus.OFFLINE
    ping_time_ms: Optional[float] = None
    endpoint_results: dict = field(default_factory=dict)
    merged_data: dict = field(default_factory=dict)
    sessions: dict = field(default_factory=dict)
    error: Optional[str] = None
    scan_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "status": self.status.value,
            "ping_time_ms": self.ping_time_ms,
            "endpoint_results": self.endpoint_results,
            "merged_data": self.merged_data,
            "error": self.error,
            "scan_time_ms": self.scan_time_ms,
        }


def parse_ip_range(range_str: str) -> list[str]:
    ips = []
    if "/" in range_str:
        import ipaddress
        try:
            network = ipaddress.ip_network(range_str, strict=False)
            for ip in network:
                if not ip.is_reserved:
                    ips.append(str(ip))
            return ips
        except ValueError:
            pass
    if "-" in range_str:
        parts = range_str.rsplit("-", 1)
        if len(parts) == 2:
            base_parts = parts[0].rsplit(".", 3)
            if len(base_parts) == 4:
                prefix = ".".join(base_parts[:3]) + "."
                start = int(base_parts[3])
                end = int(parts[1])
                for i in range(start, end + 1):
                    ips.append(f"{prefix}{i}")
                return ips
    return [range_str]


def load_ips(path: str) -> list[str]:
    ips = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            for ip in re.split(r"[,\s]+", line):
                if ip:
                    ips.append(ip)
    return ips


def ping_host(ip: str, count: int = 1, timeout: float = 2.0) -> tuple[bool, float]:
    try:
        if sys.platform.startswith("linux"):
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(int(timeout)), ip],
                capture_output=True, timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                match = re.search(r"time=([\d.]+)", result.stdout.decode())
                return True, float(match.group(1)) if match else True, 0.0
        elif sys.platform == "darwin":
            result = subprocess.run(
                ["ping", "-n", str(count), "-t", str(timeout)), ip],
                capture_output=True, timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                return True, 0.0
        else:
            result = subprocess.run(
                ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip],
                capture_output=True, timeout=timeout * count + 2,
            )
            if result.returncode == 0:
                return True, 0.0
    except Exception:
        pass
    return False, 0.0


def get_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def smart_merge(base: dict, new: dict) -> dict:
    """Merge dicts preserving non-null values."""
    for k, v in new.items():
        if k not in base:
            base[k] = v
        elif base[k] is None or base[k] == 0 or base[k] == "":
            base[k] = v
        elif isinstance(base[k], dict) and isinstance(v, dict):
            smart_merge(base[k], v)
    return base


async def scan_endpoint(
    session: Any,
    ip: str,
    endpoint: APIEndpoint,
    sessions: dict,
    timeout: float,
) -> dict:
    """Scan single endpoint."""
    url = f"http://ip}:{endpoint.path}"
    session_key = f"ip}:{endpoint.path.split('/')[1]}" if endpoint.preserve_session else "default"
    
    if session_key not in sessions:
        import aiohttp
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        sessions[session_key] = aiohttp.ClientSession(timeout=timeout_obj)
    
    sess = sessions[session_key]
    
    try:
        method = endpoint.method.value.lower()
        method_fn = getattr(sess, method)
        async with method_fn(url) as response:
            if "application/json" in response.headers.get("content-type", ""):
                return await response.json()
            return {"status": response.status}
    except Exception as e:
        return {"error": str(e)}


async def scan_device(
    ip: str,
    groups: list[EndpointGroup],
    timeout: float = 5.0,
) -> ScanResult:
    """Scan device with custom endpoints."""
    start = datetime.utcnow()
    result = ScanResult(ip=ip)
    
    pingable, ping_time = ping_host(ip)
    result.ping_time_ms = ping_time
    
    if not pingable:
        result.status = ScanStatus.OFFLINE
        result.scan_time_ms = (datetime.utcnow() - start).total_seconds() * 1000
        return result
    
    result.status = ScanStatus.PINGABLE
    result.hostname = get_hostname(ip)
    
    sessions = {}
    
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for group in groups:
                for endpoint in group.endpoints:
                    data = await scan_endpoint(session, ip, endpoint, sessions, timeout)
                    result.endpoint_results[endpoint.path] = data
                    
                    if endpoint.merge_strategy == "smart":
                        result.merged_data = smart_merge(result.merged_data, data)
                    
    except Exception as e:
        result.error = str(e)
    
    result.scan_time_ms = (datetime.utcnow() - start).total_seconds() * 1000
    return result


async def scan_ips(
    ips: list[str],
    groups: list[EndpointGroup],
    timeout: float,
    concurrency: int = 100,
) -> list[ScanResult]:
    """Scan multiple IPs."""
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_with_limit(ip: str) -> ScanResult:
        async with semaphore:
            return await scan_device(ip, groups, timeout)
    
    tasks = [scan_with_limit(ip) for ip in ips]
    return await asyncio.gather(*tasks)


def format_output(results: list[ScanResult], fmt: OutputFormat) -> str:
    if fmt == OutputFormat.JSON:
        return json.dumps([r.to_dict() for r in results])
    elif fmt == OutputFormat.JSON_PRETTY:
        return json.dumps([r.to_dict() for r in results], indent=2)
    elif fmt == OutputFormat.CSV:
        lines = ["ip,hostname,status,ping_ms,scan_time_ms"]
        for r in results:
            lines.append(f"{r.ip},{r.hostname or ''},{r.status.value},{r.ping_time_ms or ''},{r.scan_time_ms:.1f}")
        return "\n".join(lines)
    else:
        lines = [f"Scanned {len(results)} devices:\n"]
        for r in results:
            icon = "✓" if r.status == ScanStatus.ONLINE else "✗"
            lines.append(f"{icon} {r.ip}" + (f" ({r.hostname}" if r.hostname else ""))
            for path, data in r.endpoint_results.items():
                lines.append(f"  └── {path}: {len(data)} fields")
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Advanced IP Scanner")
    parser.add_argument("ips", nargs="*", help="IP addresses or ranges")
    parser.add_argument("-f", "--file", help="IP list file")
    parser.add_argument("-e", "--endpoints", help="Endpoint groups JSON file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-F", "--format", choices=["json", "json-pretty", "text", "csv"], default="json-pretty")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-c", "--concurrency", type=int, default=100)
    
    args = parser.parse_args()
    
    # Load IPs
    ip_list = []
    if args.file:
        ip_list.extend(load_ips(args.file))
    ip_list.extend(args.ips)
    ip_list = list(dict.fromkeys(ip_list))
    
    if not ip_list:
        parser.error("No IPs specified")
    
    # Load endpoints
    groups = []
    if args.endpoints:
        with open(args.endpoints) as f:
            config = json.load(f)
            for g in config.get("groups", []):
                endpoints = [APIEndpoint(**e) for e in g.get("endpoints", [])]
                groups.append(EndpointGroup(name=g["name"], endpoints=endpoints))
    
    print(f"Scanning {len(ip_list)} targets...")
    
    results = asyncio.run(scan_ips(ip_list, groups, args.timeout, args.concurrency))
    
    output = format_output(results, OutputFormat(args.format))
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
