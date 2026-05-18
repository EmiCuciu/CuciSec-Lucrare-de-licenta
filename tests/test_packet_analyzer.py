"""
Tests for PacketAnalyzer — raw byte dissection into PacketInfo.
Uses Scapy to build real raw packets. No network/DB required.
"""
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from service.packet_analyzer import PacketAnalyzer


# --- IPv4 TCP ---

def test_ipv4_tcp_basic_fields():
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.ip_src == "1.2.3.4"
    assert info.ip_dst == "5.6.7.8"
    assert info.protocol == "TCP"
    assert info.port_src == 12345
    assert info.port_dst == 80


def test_ipv4_tcp_with_payload():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=54321, dport=80) / Raw(load=payload))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.payload is not None
    assert "GET" in info.payload
    assert "example.com" in info.payload


def test_ipv4_tcp_no_payload_payload_is_none():
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=443))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.payload is None


# --- IPv4 UDP ---

def test_ipv4_udp_basic_fields():
    raw = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=53))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.protocol == "UDP"
    assert info.port_src == 53
    assert info.port_dst == 53


def test_ipv4_udp_with_payload():
    raw = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=9999, dport=80) / Raw(load=b"hello"))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.protocol == "UDP"
    assert "hello" in info.payload


# --- IPv4 ICMP ---

def test_ipv4_icmp_echo_request():
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / ICMP(type=8, code=0))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.protocol == "ICMP"
    # ICMP: port_dst = type, port_src = code
    assert info.port_dst == 8
    assert info.port_src == 0


def test_ipv4_icmp_echo_reply():
    raw = bytes(IP(src="5.6.7.8", dst="1.2.3.4") / ICMP(type=0, code=0))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.protocol == "ICMP"
    assert info.port_dst == 0  # type=0 (echo reply)


# --- IPv6 TCP ---

def test_ipv6_tcp_basic_fields():
    raw = bytes(IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=8080))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None
    assert info.ip_src == "::1"
    assert info.ip_dst == "::2"
    assert info.protocol == "TCP"
    assert info.port_dst == 8080


# --- Edge cases ---

def test_empty_bytes_returns_none():
    assert PacketAnalyzer.analyze(b"") is None


def test_none_returns_none():
    assert PacketAnalyzer.analyze(None) is None


def test_random_garbage_returns_none():
    # All-zero bytes have IP version 0 → should return None
    assert PacketAnalyzer.analyze(b"\x00" * 20) is None


def test_truncated_packet_returns_none_or_partial():
    # Only 1 byte — version bits may not even parse properly
    result = PacketAnalyzer.analyze(b"\x45")  # IPv4 header, but truncated
    # Should either return None (parse error) or a partial PacketInfo — must not raise
    # We just assert it doesn't crash
    assert result is None or result.ip_src is not None


# --- Payload encoding ---

def test_payload_utf8_text_decoded():
    payload = "UNION SELECT username FROM users".encode("utf-8")
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80) / Raw(load=payload))
    info = PacketAnalyzer.analyze(raw)
    assert info.payload is not None
    assert "UNION SELECT" in info.payload


def test_payload_with_non_utf8_bytes_does_not_crash():
    # Binary payload (e.g. binary protocol or malware) — errors='ignore' should handle it
    binary = bytes(range(256))
    raw = bytes(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80) / Raw(load=binary))
    info = PacketAnalyzer.analyze(raw)
    assert info is not None  # must not raise
