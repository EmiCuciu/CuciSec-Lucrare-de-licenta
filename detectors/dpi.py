import re
import urllib.parse
from typing import List, NamedTuple, Optional, Tuple

from loguru import logger

from domain.models import PacketInfo

HTTP_PORTS = {80, 8080, 8000, 8443}
HTTPS_PORT = 443

# Severity constants and their score values
HIGH   = "HIGH"    # 10 pts — unambiguous attack vector -> DROP + BAN
MEDIUM = "MEDIUM"  # 5  pts — strong indicator, some false-positive risk
LOW    = "LOW"     # 2  pts — suspicious but common in legitimate payloads -> DROP only

SEVERITY_SCORE = {HIGH: 10, MEDIUM: 5, LOW: 2}
BAN_THRESHOLD  = 5  # accumulated score >= BAN_THRESHOLD -> DROP + BAN


class DPIResult(NamedTuple):
    """Result returned by DPIEngine.inspect()"""
    alert: str
    should_ban: bool


class DPIEngine:
    """
    Deep Packet Inspection — Layer 7 severity-based scoring engine.

    Flow per packet:
      1. Skip non-HTTP ports (HTTPS logged explicitly)
      2. Normalize payload: URL-decode + lowercase (catches encoding bypasses)
      3. Scan all signatures, accumulate score
      4. score >= BAN_THRESHOLD -> DPIResult(alert, should_ban=True)
         score > 0              -> DPIResult(alert, should_ban=False)
         score == 0             -> None (clean)
    """

    # (compiled_pattern, severity, human_readable_label)
    _SIGNATURES: List[Tuple[re.Pattern, str, str]] = [

        # SQL Injection
        (re.compile(r"union\s+select",               re.IGNORECASE), HIGH,   "SQLi: UNION SELECT"),
        (re.compile(r"drop\s+table",                 re.IGNORECASE), HIGH,   "SQLi: DROP TABLE"),
        (re.compile(r"'\s*or\s*'1'\s*=\s*'1",        re.IGNORECASE), HIGH,   "SQLi: tautology '1'='1'"),
        (re.compile(r"\bor\b\s+[\d'\"(].*[=<>]",     re.IGNORECASE), MEDIUM, "SQLi: OR condition"),

        # Cross-Site Scripting
        (re.compile(r"<script[^>]*>",                re.IGNORECASE), HIGH,   "XSS: <script> tag"),
        (re.compile(r"javascript\s*:",               re.IGNORECASE), HIGH,   "XSS: javascript protocol"),
        (re.compile(r"\bon\w+\s*=",                  re.IGNORECASE), MEDIUM, "XSS: event handler attribute"),

        # Command Injection
        (re.compile(r";\s*(cat|ls|whoami|id|wget|curl|bash|sh)\b", re.IGNORECASE), HIGH, "Command Injection: semicolon"),
        (re.compile(r"\|\s*(cat|ls|whoami|id|wget|curl)\b",        re.IGNORECASE), HIGH, "Command Injection: pipe"),

        # Path Traversal
        (re.compile(r"(\.\./){2,}",                  re.IGNORECASE), MEDIUM, "Path Traversal: ../../"),
        (re.compile(r"/etc/passwd",                  re.IGNORECASE), LOW,    "Sensitive Path: /etc/passwd"),

        # Remote Code Execution
        (re.compile(r"\$\{jndi:(ldap|rmi|dns)://",  re.IGNORECASE), HIGH,   "Log4Shell RCE"),
        (re.compile(r"(system|exec|passthru|shell_exec)\s*\(", re.IGNORECASE), HIGH, "PHP RCE function"),
        (re.compile(r"cmd\.exe",                     re.IGNORECASE), HIGH,   "Windows RCE: cmd.exe"),
        (re.compile(r"powershell\s+-",               re.IGNORECASE), HIGH,   "Windows RCE: PowerShell"),

        # Server-Side Request Forgery
        (re.compile(r"(localhost|127\.0\.0\.1|169\.254\.169\.254)", re.IGNORECASE), MEDIUM, "SSRF: internal address"),

        # Scanner / Enumeration Fingerprinting
        (re.compile(r"User-Agent:\s*.*(sqlmap|nikto|masscan|nuclei|zgrab|nmap)", re.IGNORECASE), MEDIUM, "Scanner User-Agent"),
        (re.compile(r"Nmap\s+scan\s+report",         re.IGNORECASE), LOW,    "Nmap scan output"),
    ]

    def __init__(self):
        # instance copy allows extending signatures at runtime without touching class state
        self.signatures: List[Tuple[re.Pattern, str, str]] = list(self._SIGNATURES)

    @staticmethod
    def _normalize(payload: str) -> str:
        """
        URL-decode then lowercase payload.
        Catches trivial encoding bypasses like %75nion%20select → union select.
        """
        return urllib.parse.unquote_plus(payload).lower()

    def inspect(self, packet_info: PacketInfo) -> Optional[DPIResult]:
        """
        Inspect HTTP payload for Layer 7 attack signatures.
        :param packet_info: packet metadata (port_dst, payload required)
        :return: DPIResult or None if payload is clean / port not inspectable
        """
        port_dst = packet_info.port_dst

        if port_dst == HTTPS_PORT:
            logger.debug("[DPI] HTTPS (port 443) — TLS-encrypted payload, inspection skipped")
            return None

        if port_dst not in HTTP_PORTS:
            return None

        payload = packet_info.payload
        if not payload:
            return None

        logger.debug(f"[DPI] Inspecting payload from {packet_info.ip_src} → port {port_dst}")

        normalized = self._normalize(payload)

        total_score = 0
        hits: List[str] = []

        for pattern, severity, label in self.signatures:
            if pattern.search(normalized):
                score = SEVERITY_SCORE[severity]
                total_score += score
                hits.append(f"[{severity}] {label}")
                logger.warning(f"[DPI] Hit: {label} | severity={severity} | +{score}pts")

        if not hits:
            return None

        alert = f"score={total_score} | " + ", ".join(hits)
        should_ban = total_score >= BAN_THRESHOLD

        logger.warning(
            f"[DPI ALERT] {packet_info.ip_src} | {alert} | "
            f"verdict={'DROP+BAN' if should_ban else 'DROP only'}"
        )
        return DPIResult(alert=alert, should_ban=should_ban)