"""Tests for IP Scanner."""
import pytest
from ip_scanner import parse_ip_range, load_ips_from_file, merge_json
import tempfile
import os


def test_parse_ip_single():
    """Test parsing single IP."""
    ips = parse_ip_range("192.168.1.1")
    assert ips == ["192.168.1.1"]


def test_parse_ip_cidr():
    """Test parsing CIDR range."""
    ips = parse_ip_range("192.168.1.0/30")
    # /30 gives 4 IPs
    assert len(ips) == 4
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips


def test_parse_ip_range():
    """Test parsing range."""
    ips = parse_ip_range("192.168.1.1-5")
    assert len(ips) == 5
    assert "192.168.1.1" in ips
    assert "192.168.1.5" in ips


def test_load_ips_from_file(tmp_path):
    """Test loading IPs from file."""
    f = tmp_path / "ips.txt"
    f.write_text("192.168.1.1\n192.168.1.2\n192.168.1.3")
    
    ips = load_ips_from_file(str(f))
    assert len(ips) == 3


def test_merge_json():
    """Test JSON merging logic."""
    # Create test data
    d1 = {"a": 1, "b": None, "c": ""}
    d2 = {"a": None, "b": 2, "c": "text", "d": 4}
    
    merged = merge_json([d1, d2])
    
    assert merged["a"] == 1  # From d1
    assert merged["b"] == 2  # From d2 (d1 was None)
    assert merged["c"] == "text"  # From d2 (d1 was empty)
    assert merged["d"] == 4  # From d2


if __name__ == "__main__":
    pytest.main([__file__])
