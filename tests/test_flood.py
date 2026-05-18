"""
Tests for FloodEngine — sliding-window flood detection.
No network, no DB required. Time is manipulated via monkeypatch.
"""
import time
import pytest
from detectors.flood import FloodEngine
from domain.models import PacketInfo


def make_packet(ip: str = "10.10.10.10", protocol: str = "TCP",
                port_dst: int = 80) -> PacketInfo:
    return PacketInfo(
        ip_src=ip,
        ip_dst="5.6.7.8",
        protocol=protocol,
        port_src=12345,
        port_dst=port_dst,
    )


@pytest.fixture
def engine():
    return FloodEngine()


def flood(engine: FloodEngine, packet: PacketInfo, count: int):
    """Send `count` packets through the engine; return the last result."""
    result = None
    for _ in range(count):
        result = engine.inspect(packet)
    return result


# --- Normal traffic (no flood) ---

def test_single_tcp_packet_passes(engine):
    assert engine.inspect(make_packet(protocol="TCP")) is None


def test_single_udp_packet_passes(engine):
    assert engine.inspect(make_packet(protocol="UDP")) is None


def test_single_icmp_packet_passes(engine):
    assert engine.inspect(make_packet(protocol="ICMP")) is None


# --- TCP flood ---

def test_tcp_flood_detected(engine):
    pkt = make_packet(protocol="TCP", port_dst=80)
    result = flood(engine, pkt, engine.MAX_TCP_NEW + 1)
    assert result is not None
    assert "TCP" in result


def test_tcp_below_threshold_not_detected(engine):
    pkt = make_packet(protocol="TCP", port_dst=80)
    result = flood(engine, pkt, engine.MAX_TCP_NEW)
    assert result is None


# --- UDP flood ---

def test_udp_flood_detected(engine):
    pkt = make_packet(protocol="UDP")
    result = flood(engine, pkt, engine.MAX_UDP_NEW + 1)
    assert result is not None
    assert "UDP" in result


def test_udp_below_threshold_not_detected(engine):
    pkt = make_packet(protocol="UDP")
    result = flood(engine, pkt, engine.MAX_UDP_NEW)
    assert result is None


# --- ICMP flood ---

def test_icmp_flood_detected(engine):
    pkt = make_packet(protocol="ICMP")
    result = flood(engine, pkt, engine.MAX_ICMP + 1)
    assert result is not None
    assert "ICMP" in result


def test_icmp_below_threshold_not_detected(engine):
    pkt = make_packet(protocol="ICMP")
    result = flood(engine, pkt, engine.MAX_ICMP)
    assert result is None


# --- Per-port TCP thresholds ---

def test_ssh_port_has_lower_threshold(engine):
    # SSH threshold = 10 (Config.PER_PORT_TCP_THRESHOLDS[22])
    pkt = make_packet(protocol="TCP", port_dst=22)
    result = flood(engine, pkt, 11)
    assert result is not None
    assert "TCP" in result


def test_ssh_port_below_threshold_passes(engine):
    pkt = make_packet(protocol="TCP", port_dst=22)
    result = flood(engine, pkt, 10)
    assert result is None


def test_mysql_port_has_lower_threshold(engine):
    pkt = make_packet(protocol="TCP", port_dst=3306)
    result = flood(engine, pkt, 21)
    assert result is not None


# --- Whitelist ---

def test_loopback_is_not_flood_banned(engine):
    pkt = make_packet(ip="127.0.0.1", protocol="ICMP")
    result = flood(engine, pkt, engine.MAX_ICMP + 100)
    assert result is None


def test_whitelist_cidr_10_0_2_0_not_banned(engine):
    pkt = make_packet(ip="10.0.2.5", protocol="TCP", port_dst=80)
    result = flood(engine, pkt, engine.MAX_TCP_NEW + 100)
    assert result is None


def test_non_whitelisted_ip_gets_banned(engine):
    pkt = make_packet(ip="8.8.8.8", protocol="TCP", port_dst=80)
    result = flood(engine, pkt, engine.MAX_TCP_NEW + 1)
    assert result is not None


# --- Sliding window expiry ---

def test_flood_resets_after_window(engine, monkeypatch):
    pkt = make_packet(ip="9.9.9.9", protocol="TCP", port_dst=80)
    # Fill up to just below threshold
    flood(engine, pkt, engine.MAX_TCP_NEW)

    # Advance time past TIME_WINDOW so old timestamps expire
    future = time.time() + engine.TIME_WINDOW + 1
    monkeypatch.setattr(time, "time", lambda: future)

    # Single packet after window reset — should not trigger
    result = engine.inspect(pkt)
    assert result is None


# --- Edge cases ---

def test_none_ip_returns_none(engine):
    pkt = PacketInfo(ip_src=None, ip_dst="5.6.7.8", protocol="TCP",
                     port_src=1234, port_dst=80)
    assert engine.inspect(pkt) is None


def test_unknown_protocol_not_detected(engine):
    pkt = make_packet(protocol="UNKNOWN")
    result = flood(engine, pkt, 1000)
    assert result is None


def test_different_ips_tracked_independently(engine):
    # IP A floods, IP B stays clean
    pkt_a = make_packet(ip="1.1.1.1", protocol="TCP", port_dst=80)
    pkt_b = make_packet(ip="2.2.2.2", protocol="TCP", port_dst=80)

    flood(engine, pkt_a, engine.MAX_TCP_NEW + 1)
    result_b = engine.inspect(pkt_b)
    assert result_b is None
