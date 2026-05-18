"""
Tests for HoneyportEngine — trap port detection.
No network, no DB required.
"""
import pytest
from detectors.honeyport import HoneyportEngine
from domain.models import PacketInfo
from utils.config import Config


def make_packet(protocol: str, port_dst: int) -> PacketInfo:
    return PacketInfo(
        ip_src="1.2.3.4",
        ip_dst="5.6.7.8",
        protocol=protocol,
        port_src=12345,
        port_dst=port_dst,
    )


@pytest.fixture
def engine():
    return HoneyportEngine(Config.HONEY_PORTS)


# --- Honeyport hits ---

@pytest.mark.parametrize("port", Config.HONEY_PORTS)
def test_tcp_to_honeyport_is_detected(engine, port):
    pkt = make_packet("TCP", port)
    result = engine.inspect(pkt)
    assert result is not None
    assert str(port) in result


@pytest.mark.parametrize("port", Config.HONEY_PORTS)
def test_udp_to_honeyport_is_detected(engine, port):
    pkt = make_packet("UDP", port)
    result = engine.inspect(pkt)
    assert result is not None
    assert str(port) in result


# --- Normal ports ---

@pytest.mark.parametrize("port", [80, 443, 22, 8080, 8000, 8443])
def test_tcp_to_normal_port_passes(engine, port):
    assert engine.inspect(make_packet("TCP", port)) is None


@pytest.mark.parametrize("port", [53, 123, 161])
def test_udp_to_normal_port_passes(engine, port):
    assert engine.inspect(make_packet("UDP", port)) is None


# --- Non-TCP/UDP protocols ignore honeyports ---

def test_icmp_on_honeyport_is_ignored(engine):
    pkt = make_packet("ICMP", Config.HONEY_PORTS[0])
    assert engine.inspect(pkt) is None


def test_unknown_protocol_on_honeyport_is_ignored(engine):
    pkt = make_packet("UNKNOWN", Config.HONEY_PORTS[0])
    assert engine.inspect(pkt) is None


# --- Custom honeyport list ---

def test_custom_honey_ports():
    custom_engine = HoneyportEngine([1234, 5678])
    assert custom_engine.inspect(make_packet("TCP", 1234)) is not None
    assert custom_engine.inspect(make_packet("TCP", 80)) is None


def test_default_ports_used_when_none_provided():
    engine = HoneyportEngine(None)
    assert engine.inspect(make_packet("TCP", 23)) is not None
    assert engine.inspect(make_packet("TCP", 9999)) is not None
