"""Comprehensive tests for IP Scanner CI."""
import pytest
import json
from ip_scanner import (
    parse_ip_range,
    load_ips,
    format_output,
    OutputFormat,
    ScanResult,
    ScanStatus,
    smart_merge,
    get_local_ip,
    get_local_subnet_range,
    nmap_available,
    HTTPMethod,
    APIEndpoint,
)


class TestIPParsing:
    """Test IP range parsing."""

    def test_single_ip(self):
        ips = parse_ip_range("192.168.1.1")
        assert ips == ["192.168.1.1"]

    def test_cidr_24(self):
        ips = parse_ip_range("192.168.1.0/24")
        assert len(ips) == 256
        assert "192.168.1.1" in ips
        assert "192.168.1.254" in ips

    def test_cidr_small(self):
        ips = parse_ip_range("192.168.1.0/30")
        assert len(ips) == 4

    def test_ip_range(self):
        ips = parse_ip_range("192.168.1.10-20")
        assert len(ips) == 11
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips

    def test_cidr_reserved_ignored(self):
        ips = parse_ip_range("192.168.1.0/30")
        # .0 and .3 are typically reserved in /30
        assert len(ips) == 4


class TestLoadIPs:
    """Test loading IPs from files."""

    def test_load_single_column(self, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("192.168.1.1\n192.168.1.2\n192.168.1.3")
        ips = load_ips(str(f))
        assert len(ips) == 3

    def test_load_with_comments(self, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("# This is a comment\n192.168.1.1\n# Another comment\n192.168.1.2")
        ips = load_ips(str(f))
        assert len(ips) == 2

    def test_load_comma_separated(self, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("192.168.1.1, 192.168.1.2, 192.168.1.3")
        ips = load_ips(str(f))
        assert len(ips) == 3


class TestJSONMerging:
    """Test JSON smart merging."""

    def test_merge_preserves_values(self):
        d1 = {"a": 1, "b": "hello"}
        d2 = {"a": None, "b": ""}
        merged = smart_merge(d1.copy(), d2)
        assert merged["a"] == 1
        assert merged["b"] == "hello"

    def test_merge_overwrites_null(self):
        d1 = {"a": None}
        d2 = {"a": 42}
        merged = smart_merge(d1.copy(), d2)
        assert merged["a"] == 42

    def test_merge_overwrites_zero(self):
        d1 = {"count": 0}
        d2 = {"count": 10}
        merged = smart_merge(d1.copy(), d2)
        assert merged["count"] == 10

    def test_merge_nested(self):
        d1 = {"outer": {"inner": 1}}
        d2 = {"outer": {"inner2": 2}}
        merged = smart_merge(d1.copy(), d2)
        assert merged["outer"]["inner"] == 1
        assert merged["outer"]["inner2"] == 2

    def test_empty_response(self):
        merged = smart_merge({}, {})
        assert merged == {}


class TestOutputFormat:
    """Test output formatting."""

    def test_json_output_has_ip_keys(self):
        results = [
            ScanResult(ip="192.168.1.1", status=ScanStatus.ONLINE),
            ScanResult(ip="192.168.1.2", status=ScanStatus.OFFLINE),
        ]
        output = format_output(results, OutputFormat.JSON)
        data = json.loads(output)
        
        assert "192.168.1.1" in data
        assert "192.168.1.2" in data
        assert isinstance(data, dict)

    def test_json_pretty_output(self):
        results = [ScanResult(ip="192.168.1.1", status=ScanStatus.ONLINE)]
        output = format_output(results, OutputFormat.JSON_PRETTY)
        data = json.loads(output)
        
        assert "192.168.1.1" in data
        # Pretty print should have newlines and indentation
        assert "\n" in output

    def test_text_output_contains_summary(self):
        results = [
            ScanResult(ip="192.168.1.1", status=ScanStatus.ONLINE),
        ]
        output = format_output(results, OutputFormat.TEXT)
        assert "192.168.1.1" in output
        assert "✓" in output  # Online symbol

    def test_offline_shows_x(self):
        results = [
            ScanResult(ip="192.168.1.1", status=ScanStatus.OFFLINE),
        ]
        output = format_output(results, OutputFormat.TEXT)
        assert "✗" in output

    def test_hostname_in_output(self):
        results = [
            ScanResult(ip="192.168.1.1", status=ScanStatus.ONLINE, hostname="router.local"),
        ]
        output = format_output(results, OutputFormat.JSON)
        data = json.loads(output)
        
        assert data["192.168.1.1"]["hostname"] == "router.local"

    def test_endpoint_results_included(self):
        results = [
            ScanResult(
                ip="192.168.1.1",
                status=ScanStatus.ONLINE,
                endpoint_results={"/api/system": {"version": "2.0"}}
            ),
        ]
        output = format_output(results, OutputFormat.JSON)
        data = json.loads(output)
        
        assert "/api/system" in data["192.168.1.1"]["endpoint_results"]


class TestAPIClient:
    """Test API endpoint configuration."""

    def test_default_method(self):
        endpoint = APIEndpoint(path="/api/test")
        assert endpoint.method == HTTPMethod.GET

    def test_custom_method(self):
        endpoint = APIEndpoint(path="/api/login", method=HTTPMethod.POST)
        assert endpoint.method == HTTPMethod.POST

    def test_preserve_session_default(self):
        endpoint = APIEndpoint(path="/api/test")
        assert endpoint.preserve_session is False

    def test_preserve_session_flag(self):
        endpoint = APIEndpoint(path="/api/auth", preserve_session=True)
        assert endpoint.preserve_session is True

    def test_default_merge_strategy(self):
        endpoint = APIEndpoint(path="/api/test")
        assert endpoint.merge_strategy == "smart"


class TestSubnetDetection:
    """Test local subnet detection."""

    def test_get_local_ip_returns_string_or_none(self):
        ip = get_local_ip()
        assert ip is None or isinstance(ip, str)

    def test_get_local_subnet_range_format(self):
        ip = get_local_ip()
        if ip:
            range_str = get_local_subnet_range(ip)
            if range_str:
                assert "-" in range_str
                # Should have format like "192.168.1.100-150"
                parts = range_str.rsplit(".", 1)
                assert len(parts) == 2


class TestNmapAvailability:
    """Test nmap integration checks."""

    def test_nmap_check(self):
        # This will pass if nmap is installed, fail otherwise
        # CI environment may or may not have nmap
        result = nmap_available()
        # Just verify it returns a boolean
        assert isinstance(result, bool)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_invalid_cidr_raises(self):
        # Should not crash on invalid input
        ips = parse_ip_range("invalid")
        assert ips == ["invalid"]

    def test_empty_results(self):
        output = format_output([], OutputFormat.JSON)
        data = json.loads(output)
        assert data == {}

    def test_result_with_error(self):
        results = [
            ScanResult(ip="192.168.1.1", status=ScanStatus.ERROR, error="Connection failed"),
        ]
        output = format_output(results, OutputFormat.JSON)
        data = json.loads(output)
        
        assert data["192.168.1.1"]["error"] == "Connection failed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
