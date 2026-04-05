from netfilterqueue import NetfilterQueue

from core.actions import FirewallActions
from core.analyzer import PacketAnalyzer
from core.rule_engine import RuleEngine
from detectors.dpi import DPIEngine
from detectors.honeyport import HoneyportEngine


class PacketInterceptor:
    """
    Class responsible with packet takeover from NFQUEUE, using NetFilterQueue, and sending them to UserSpace
    """

    def __init__(self, queue_num: int = 1):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False
        self.analyzer = PacketAnalyzer()
        self.actions = FirewallActions()
        self.rule_engine = RuleEngine()
        self.dpi = DPIEngine()
        self.honeyport = HoneyportEngine()

    def _process_packet(self, packet):
        """
        Callback function for every packet from the queue
        turns raw packet into scapy packet and analyze it
        :param packet: packet from NFQUEUE
        :return: None
        :note: verdict (accept, drop, modify) will be decided based on the analysis logic implemented in this function

        FLOW:
            NFTABLE IPS FLOOD (KERNEL)
                -> RULE_ENGINE( STATIC RULE - DROP)
                    -> HONEYPORT
                        -> DPI
        """

        raw_payload = packet.get_payload()

        packet_data = self.analyzer.analyze(raw_payload)

        # show what is in packet_data
        if packet_data:
            print(f"\nPacket: Protocol: {packet_data['protocol']} "
                  f"| IP_SRC: {packet_data['ip_src']} : PORT_SRC: {packet_data['port_src']} "
                  f"| IP_DST: {packet_data['ip_dst']} : PORT_DST: {packet_data['port_dst']}")

            if packet_data["payload"]:
                print(f"Payload: {packet_data['payload']} ...")




            #### Rule Engine
            decision = self.rule_engine.evaluate(packet_data)

            if decision == "DROP":
                print("DROP: STATIC RULE")
                self.actions.drop_packet(packet, packet_data, "RULE_ENGINE_DROP")
                return



            #### Honeyport
            honey_alert = self.honeyport.inspect(packet_data)
            if honey_alert:
                print(f"HONEYPORT ALERT: {honey_alert}")
                self.actions.drop_packet(packet, packet_data, f"HONEYPORT_DROP {honey_alert}")
                self.actions.ban_ip(packet_data["ip_src"], reason=honey_alert)
                return




            #### DPI
            dpi_alert = self.dpi.inspect(packet_data)

            if dpi_alert:
                print(f"DPI ALERT: {dpi_alert}")
                self.actions.drop_packet(packet, packet_data, f"DPI_DROP {dpi_alert}")
                self.actions.ban_ip(packet_data["ip_src"], reason=dpi_alert)
                return

            # Rule Engine
            if decision == "ACCEPT":
                print("ACCEPT: STATIC RULE")
                self.actions.accept_packet(packet, packet_data, "RULE_ENGINE_ACCEPT")
                return

            # Default policy -
            print("ACCEPT: DEFAULT POLICY")
            self.actions.accept_packet(packet, packet_data, "DEFAULT_ACCEPT")

        else:
            print("Malformed packet or non IP header detected, instant DROP")

            bad_packet_data = {
                "ip_src": "MALFORMED",
                "ip_dst": "MALFORMED",
                "protocol": "UNKNOWN"
            }

            self.actions.drop_packet(packet,bad_packet_data, "BAD PACKET: MALFORMED OR NON-IP")

    def start(self):
        """
        Start packet interceptions
        bind NFQUEUE to the callback function that will process each packet
        :return:
        """

        try:

            self.nfqueue.bind(self.queue_num, self._process_packet, max_len=8192)
            self.is_running = True
            print(f"\nPacket Interceptor starts. Listen on NFQUEUE {self.queue_num} (max 8192 packets) .. ")

            self.nfqueue.run()  # blocking call, will keep the interceptor running until interrupted

        except KeyboardInterrupt:
            self.stop()

        except Exception as e:
            print(f"\nError in Interceptor: {e}")
            self.stop()



    def stop(self):
       """
       Stops interception and free resources
       :return:
       """

       if self.is_running:
           print("\nStop interception and free kernel connection")
           self.nfqueue.unbind()
           self.is_running = False

           self.actions.stop_worker()
           print("Database background worker stopped.")


if __name__ == "__main__":
    firewall_interceptor = PacketInterceptor(queue_num=1)
    firewall_interceptor.start()