"""
Tests for RuleEngine — in-memory rule evaluation + IP matching.
RuleRepository is mocked — no DB required.
"""
import pytest
from unittest.mock import MagicMock
from service.rule_engine import RuleEngine
from domain.models import RuleModel, PacketInfo


def make_engine(rules: list) -> RuleEngine:
    mock_repo = MagicMock()
    mock_repo.get_enabled.return_value = rules
    return RuleEngine(rule_repo=mock_repo)


def make_packet(ip_src="1.2.3.4", protocol="TCP",
                port_src=12345, port_dst=80) -> PacketInfo:
    return PacketInfo(
        ip_src=ip_src,
        ip_dst="5.6.7.8",
        protocol=protocol,
        port_src=port_src,
        port_dst=port_dst,
    )


# --- is_ip_match (static, no DB) ---

class TestIsIpMatch:
    def test_wildcard_matches_any_ip(self):
        assert RuleEngine.is_ip_match("*", "1.2.3.4") is True

    def test_empty_string_matches_any_ip(self):
        assert RuleEngine.is_ip_match("", "1.2.3.4") is True

    def test_exact_match(self):
        assert RuleEngine.is_ip_match("1.2.3.4", "1.2.3.4") is True

    def test_exact_no_match(self):
        assert RuleEngine.is_ip_match("1.2.3.4", "1.2.3.5") is False

    def test_cidr_match_inside_network(self):
        assert RuleEngine.is_ip_match("192.168.1.0/24", "192.168.1.100") is True

    def test_cidr_no_match_outside_network(self):
        assert RuleEngine.is_ip_match("192.168.1.0/24", "192.168.2.1") is False

    def test_cidr_slash32_exact(self):
        assert RuleEngine.is_ip_match("10.0.0.1/32", "10.0.0.1") is True
        assert RuleEngine.is_ip_match("10.0.0.1/32", "10.0.0.2") is False

    def test_malformed_rule_ip_falls_back_to_string_compare(self):
        assert RuleEngine.is_ip_match("not_an_ip", "1.2.3.4") is False
        assert RuleEngine.is_ip_match("not_an_ip", "not_an_ip") is True

    def test_none_rule_ip_matches_anything(self):
        assert RuleEngine.is_ip_match(None, "1.2.3.4") is True


# --- evaluate: no rules ---

def test_no_rules_returns_none_action():
    engine = make_engine([])
    action, zone = engine.evaluate(make_packet())
    assert action is None
    assert zone == ""


def test_none_packet_returns_none():
    engine = make_engine([])
    action, zone = engine.evaluate(None)
    assert action is None


# --- evaluate: IP matching ---

def test_exact_ip_rule_matches(make_drop_rule_factory=None):
    rule = RuleModel(ip_src="1.2.3.4", action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, zone = engine.evaluate(make_packet(ip_src="1.2.3.4"))
    assert action == "DROP"
    assert zone == "WAN"


def test_exact_ip_rule_no_match(make_drop_rule_factory=None):
    rule = RuleModel(ip_src="9.9.9.9", action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(ip_src="1.2.3.4"))
    assert action is None


def test_cidr_rule_matches_ip_in_range():
    rule = RuleModel(ip_src="10.0.0.0/8", action="DROP", zone="LAN")
    engine = make_engine([rule])
    action, zone = engine.evaluate(make_packet(ip_src="10.5.6.7"))
    assert action == "DROP"
    assert zone == "LAN"


def test_wildcard_rule_matches_any_ip():
    rule = RuleModel(ip_src="*", action="ACCEPT", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(ip_src="8.8.8.8"))
    assert action == "ACCEPT"


# --- evaluate: protocol matching ---

def test_protocol_rule_matches(make_drop_rule_factory=None):
    rule = RuleModel(ip_src="*", protocol="UDP", action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(protocol="UDP"))
    assert action == "DROP"


def test_protocol_rule_no_match_different_protocol():
    rule = RuleModel(ip_src="*", protocol="UDP", action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(protocol="TCP"))
    assert action is None


def test_none_protocol_in_rule_matches_any():
    rule = RuleModel(ip_src="*", protocol=None, action="DROP", zone="WAN")
    engine = make_engine([rule])
    for proto in ("TCP", "UDP", "ICMP"):
        action, _ = engine.evaluate(make_packet(protocol=proto))
        assert action == "DROP"


# --- evaluate: port matching ---

def test_port_matches_dst_port():
    rule = RuleModel(ip_src="*", port=80, action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(port_dst=80))
    assert action == "DROP"


def test_port_matches_src_port():
    rule = RuleModel(ip_src="*", port=12345, action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(port_src=12345, port_dst=80))
    assert action == "DROP"


def test_port_no_match():
    rule = RuleModel(ip_src="*", port=443, action="DROP", zone="WAN")
    engine = make_engine([rule])
    action, _ = engine.evaluate(make_packet(port_dst=80))
    assert action is None


# --- evaluate: first-match wins ---

def test_first_rule_wins():
    rules = [
        RuleModel(ip_src="*", action="DROP",   zone="WAN"),
        RuleModel(ip_src="*", action="ACCEPT", zone="WAN"),
    ]
    engine = make_engine(rules)
    action, _ = engine.evaluate(make_packet())
    assert action == "DROP"


def test_first_matching_rule_wins_skip_non_matching():
    rules = [
        RuleModel(ip_src="9.9.9.9", action="ACCEPT", zone="WAN"),  # won't match
        RuleModel(ip_src="*",       action="DROP",   zone="WAN"),  # will match
    ]
    engine = make_engine(rules)
    action, _ = engine.evaluate(make_packet(ip_src="1.2.3.4"))
    assert action == "DROP"


# --- evaluate: combined conditions ---

def test_all_conditions_must_match():
    rule = RuleModel(ip_src="1.2.3.4", protocol="TCP", port=80, action="DROP", zone="WAN")
    engine = make_engine([rule])

    # All match
    assert engine.evaluate(make_packet(ip_src="1.2.3.4", protocol="TCP", port_dst=80))[0] == "DROP"
    # Wrong IP
    assert engine.evaluate(make_packet(ip_src="1.2.3.5", protocol="TCP", port_dst=80))[0] is None
    # Wrong protocol
    assert engine.evaluate(make_packet(ip_src="1.2.3.4", protocol="UDP", port_dst=80))[0] is None
    # Wrong port
    assert engine.evaluate(make_packet(ip_src="1.2.3.4", protocol="TCP", port_dst=443))[0] is None


# --- reload_rules ---

def test_reload_rules_picks_up_new_rules():
    mock_repo = MagicMock()
    mock_repo.get_enabled.return_value = []
    engine = RuleEngine(rule_repo=mock_repo)

    assert engine.evaluate(make_packet())[0] is None

    new_rule = RuleModel(ip_src="*", action="DROP", zone="WAN")
    mock_repo.get_enabled.return_value = [new_rule]
    engine.reload_rules()

    assert engine.evaluate(make_packet())[0] == "DROP"
