"""
Advanced IP Scanner CLI - Network discovery with custom endpoints.
"""

from __future__ import annotations
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
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
                ["ping", "-c", str(count), "-t", str(int(timeout)), ip],
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
    """Scan a single endpoint."""
    url = f"http://{ip}:{endpoint.path}"
    session_key = f"{ip}:{endpoint.path.split('/')[1]}" if endpoint.preserve_session else "default"
    
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
    # Build dict with IP as key
    output_dict = {r.ip: {
        "hostname": r.hostname,
        "status": r.status.value,
        "ping_time_ms": r.ping_time_ms,
        "endpoint_results": r.endpoint_results,
        "merged_data": r.merged_data,
        "error": r.error,
        "scan_time_ms": round(r.scan_time_ms, 1),
    } for r in results}
    
    if fmt == OutputFormat.JSON:
        return json.dumps(output_dict)
    elif fmt == OutputFormat.JSON_PRETTY:
        return json.dumps(output_dict, indent=2)
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


def get_local_ip() -> Optional[str]:
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_subnet_range(base_ip: Optional[str] = None, start: int = 100, end: int = 150) -> Optional[str]:
    """Get subnet range based on local IP.
    
    Example: 192.168.8.15 -> 192.168.8.100-150
    """
    if not base_ip:
        base_ip = get_local_ip()
    
    if not base_ip:
        return None
    
    parts = base_ip.rsplit(".", 1)
    if len(parts) == 2:
        prefix = parts[0]
        return f"{prefix}.{start}-{end}"
    
    return None


def nmap_available() -> bool:
    """Check if nmap is installed."""
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def run_nmap_scan(ip: str, ports: str = None, arguments: str = "-sV -sC --open") -> dict:
    """Run nmap scan on an IP address.
    
    Args:
        ip: Target IP address
        ports: Specific ports to scan (e.g., "80,443,22")
        arguments: Nmap arguments (default: service detection + scripts)
    
    Returns:
        Dict with nmap results
    """
    if not nmap_available():
        return {"error": "nmap not installed"}
    
    cmd = ["nmap", ip]
    
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.append("-p-")  # Scan all ports
    
    cmd.extend(arguments.split())
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        
        if result.returncode != 0:
            return {"error": result.stderr}
        
        # Parse basic output
        output = result.stdout
        host_script = {"output": output}
        
        # Extract port info
        ports_info = []
        in_port_section = False
        
        for line in output.splitlines():
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                in_port_section = True
                ports_info.append(line)
            elif in_port_section and not line:
                in_port_section = False
        
        host_script["ports"] = ports_info
        
        return host_script
        
    except subprocess.TimeoutExpired:
        return {"error": "nmap scan timed out"}
    except Exception as e:
        return {"error": str(e)}


async def nmap_scan_ips(ips: list[str], ports: str = None, arguments: str = "-sV -sC --open") -> dict:
    """Run nmap scan on multiple IPs.
    
    Uses ThreadPoolExecutor for concurrent nmap scans.
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(run_nmap_scan, ip, ports, arguments): ip 
            for ip in ips
        }
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                results[ip] = {"error": str(e)}
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Advanced IP Scanner")
    parser.add_argument("ips", nargs="*", help="IP addresses or ranges")
    parser.add_argument("-f", "--file", help="IP list file")
    parser.add_argument("-e", "--endpoints", help="Endpoint groups JSON file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-F", "--format", choices=["json", "json-pretty", "text", "csv"], default="json-pretty")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-c", "--concurrency", type=int, default=100)
    parser.add_argument("--auto-subnet", action="store_true", help="Auto-detect local subnet and scan (default: .100-.150)")
    # Nmap options
    parser.add_argument("--nmap", action="store_true", help="Run nmap scan on discovered hosts")
    parser.add_argument("--nmap-ports", help="Nmap ports to scan (e.g., '80,443,22')")
    parser.add_argument("--nmap-args", default="-sV -sC --open", help="Nmap arguments (default: -sV -sC --open)")
    
    args = parser.parse_args()
    
    # Auto-detect local subnet
    if args.auto_subnet:
        local_ip = get_local_ip()
        if local_ip:
            subnet = get_local_subnet_range(local_ip)
            if subnet:
                print(f"Local IP: {local_ip}")
                print(f"Auto-detected subnet: {subnet}")
                args.ips.append(subnet)
        else:
            print("Could not detect local IP", file=sys.stderr)
            sys.exit(1)
    
    # Load IPs
    ip_list = []
    if args.file:
        ip_list.extend(load_ips(args.file))
    ip_list.extend(args.ips)
    ip_list = list(dict.fromkeys(ip_list))
    
    if not ip_list:
        parser.print_help()
        parser.error("No IPs specified. Use --auto-subnet or provide IPs manually.")
    
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
    
    # Run nmap scan if requested
    if args.nmap:
        if not nmap_available():
            print("Warning: nmap not installed. Skipping nmap scan.")
        else:
            print(f"Running nmap scan on {len(results)} hosts...")
            nmap_results = asyncio.run(nmap_scan_ips(
                [r.ip for r in results],
                args.nmap_ports,
                args.nmap_args
            ))
            
            # Merge nmap results into existing results
            for r in results:
                if r.ip in nmap_results:
                    r.endpoint_results["nmap"] = nmap_results[r.ip]
    
    output = format_output(results, OutputFormat(args.format))
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
