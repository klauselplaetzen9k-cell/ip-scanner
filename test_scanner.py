"""Tests for IP Scanner."""
import pytest
from ip_scanner import parse_ip_range, merge_json


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


def test_merge_json():
    """Test JSON merging logic."""
    d1 = {"a": 1, "b": None, "c": ""}
    d2 = {"a": None, "b": 2, "c": "text", "d": 4}
    
    merged = merge_json([d1, d2])
    
    assert merged["a"] == 1
    assert merged["b"] == 2
    assert merged["c"] == "text"
    assert merged["d"] == 4


def test_merge_json_preserves_values():
    """Test that existing values are preserved."""
    d1 = {"value": 100}
    d2 = {"value": None}
    
    merged = merge_json([d1, d2])
    assert merged["value"] == 100  # Preserved from d1


def test_merge_json_empty_arrays():
    """Test merging with empty arrays."""
    d1 = {"items": [1, 2, 3]}
    d2 = {"items": []}
    
    merged = merge_json([d1, d2])
    assert merged["items"] == [1, 2, 3]


if __name__ == "__main__":
    pytest.main([__file__])
