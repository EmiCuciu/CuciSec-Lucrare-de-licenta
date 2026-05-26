import re
import urllib.parse
from typing import List, Optional, Tuple

from loguru import logger

from domain.models import PacketInfo

HTTP_PORTS = {80, 8080, 8000, 8443}
HTTPS_PORT = 443

class DPIEngine:
    """
    Deep Packet Inspection — Layer 7 attack signature detection engine.
    Any match is considered a high-severity threat.
    """

    _SIGNATURES: List[Tuple[re.Pattern, str]] = [

        # SQL Injection
        (re.compile(r"union\s+select",               re.IGNORECASE), "SQLi: UNION SELECT"),
        (re.compile(r"drop\s+table",                 re.IGNORECASE), "SQLi: DROP TABLE"),
        (re.compile(r"'\s*or\s*'1'\s*=\s*'1",        re.IGNORECASE), "SQLi: tautology '1'='1'"),
        (re.compile(r"\bor\b\s+[\d'\"(].*[=<>]",     re.IGNORECASE), "SQLi: OR condition"),

        # Cross-Site Scripting
        (re.compile(r"<script[^>]*>",                re.IGNORECASE), "XSS: <script> tag"),
        (re.compile(r"javascript\s*:",               re.IGNORECASE), "XSS: javascript protocol"),
        (re.compile(r"\bon\w+\s*=",                  re.IGNORECASE), "XSS: event handler attribute"),

        # Command Injection
        (re.compile(r";\s*(cat|ls|whoami|id|wget|curl|bash|sh)\b", re.IGNORECASE), "Command Injection: semicolon"),
        (re.compile(r"\|\s*(cat|ls|whoami|id|wget|curl)\b",        re.IGNORECASE), "Command Injection: pipe"),

        # Path Traversal
        (re.compile(r"(\.\./){2,}",                  re.IGNORECASE), "Path Traversal: ../../"),
        (re.compile(r"/etc/passwd",                  re.IGNORECASE), "Sensitive Path: /etc/passwd"),

        # Remote Code Execution
        (re.compile(r"\$\{jndi:(ldap|rmi|dns)://",  re.IGNORECASE), "Log4Shell RCE"),
        (re.compile(r"(system|exec|passthru|shell_exec)\s*\(", re.IGNORECASE), "PHP RCE function"),
        (re.compile(r"cmd\.exe",                     re.IGNORECASE), "Windows RCE: cmd.exe"),
        (re.compile(r"powershell\s+-",               re.IGNORECASE), "Windows RCE: PowerShell"),

        # Server-Side Request Forgery
        (re.compile(r"(localhost|127\.0\.0\.1|169\.254\.169\.254)", re.IGNORECASE), "SSRF: internal address"),

        # Scanner / Enumeration Fingerprinting
        (re.compile(r"User-Agent:\s*.*(sqlmap|nikto|masscan|nuclei|zgrab|nmap)", re.IGNORECASE), "Scanner User-Agent"),
        (re.compile(r"Nmap\s+scan\s+report",         re.IGNORECASE), "Nmap scan output"),
    ]

    def __init__(self):
        self.signatures: List[Tuple[re.Pattern, str]] = list(self._SIGNATURES)

    @staticmethod
    def _normalize(payload: str) -> str:
        return urllib.parse.unquote_plus(payload).lower()

    def inspect(self, packet_info: PacketInfo) -> Optional[str]:
        """
        Inspect HTTP payload for Layer 7 attack signatures.
        :param packet_info: packet metadata (port_dst, payload required)
        :return: verdict
        """
        logger.debug("[DPI] - INSPECTING...")

        port_dst = packet_info.port_dst

        if port_dst == HTTPS_PORT:
            logger.debug("[DPI] HTTPS (port 443) — TLS-encrypted payload, inspection skipped")
            return None

        if port_dst not in HTTP_PORTS:
            return None

        payload = packet_info.payload

        logger.debug(f"[DPI] Payload: {payload}")

        if not payload:
            logger.debug(f"[DPI] No payload from {packet_info.ip_src} -> port {port_dst}, skipping")
            return None

        logger.debug(f"[DPI] Inspecting payload from {packet_info.ip_src} -> port {port_dst}")

        normalized = self._normalize(payload)

        for pattern, label in self.signatures:
            if pattern.search(normalized):
                logger.warning(f"[DPI ALERT] {packet_info.ip_src} | {label} | verdict=DROP+BAN")
                return f"DPI HIT: {label}"

        return None