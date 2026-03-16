from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


class PacketAnalyzer:
    """
    Class responsible for packet dissection, raw_packets with raw_bytes
    Transform byte string into a structured dictionary with IP, Port, Protocol, Payload
    """

    def analyze(self, raw_payload: bytes) -> dict:
        """
        Packet dissection function, transform raw_packet into a structured dictionary with network metadata
        :param raw_payload: byte string from NFQUEUE
        :return: packet_info : dictionary [ ip_src, ip_dst, protocol, port_src, port_dst, payload ]
        :return: None : if packet doesn't have IP layer
        """

        packet = IP(raw_payload)

        if not packet.haslayer(IP):
            return None

        # Extract basic metadata ( Layer 3 )
        packet_info = {
            "ip_src": packet[IP].src,
            "ip_dst": packet[IP].dst,
            "protocol": "UNKNOWN",
            "port_src": None,
            "port_dst": None,
            "payload": None
        }

        # Identify protocol and ports ( Layer 4 )
        if packet.haslayer(TCP):
            packet_info["protocol"] = "TCP"
            packet_info["port_src"] = packet[TCP].sport
            packet_info["port_dst"] = packet[TCP].dport

        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            packet_info["port_src"] = packet[UDP].sport
            packet_info["port_dst"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            # ICMP doesn't have ports, but we can use type and code to identify the message type
            # type 8 = "echo request"
            # type 0 = "echo reply"
            packet_info["protocol"] = "ICMP"
            packet_info["port_dst"] = packet[ICMP].type

        # Extract the payload for DPI  ( Layer 7 )
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load

            try:
                # try to make readable text ( for SQLI and XSS atacks )
                packet_info["payload"] = raw_data.decode('utf-8', errors='ignore')

            except Exception:
                # if it is binary format, keep it as string representation of bytes (file transfer, malware, etc.)
                packet_info["payload"] = str(raw_data)

        return packet_info
