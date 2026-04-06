import re

from loguru import logger


class DPIEngine:
    """
    Deep Packet Inspection -> (Layer 7)
    This class analyze the payload to find signatures of known attacks.
    use regex
    """

    def __init__(self):
        self.malicious_signatures = [
            re.compile(r"union\s+select", re.IGNORECASE),
            re.compile(r"drop\s+table", re.IGNORECASE),
            re.compile(r"or\s+1=1", re.IGNORECASE),
            re.compile(r"<script>", re.IGNORECASE),
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"cmd\.exe", re.IGNORECASE),
            re.compile(r"nmap", re.IGNORECASE),
            re.compile(r"nikto", re.IGNORECASE)
        ]

    def inspect(self, packet_data: dict) -> str:
        """
        scans packet payload
        :param packet_data:
        :return: string with malitious context
        """
        payload = packet_data.get("payload")

        if not payload:
            return None

        for pattern in self.malicious_signatures:
            if pattern.search(payload):
                logger.warning(f"[DPI ALERT] Attack detected: Signature '{pattern.pattern}'")
                return f"Attack detected: Signature '{pattern.pattern}'"

        return None
