from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

class PacketInterceptor:
    """
    Class responsible with packet tackover from NFQUEUE and sending to NetFilterQueue
    """

    def __init__(self, queue_num: int = 1):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False

    def _process_packet(self, packet):
        """
        Callback funtion for every packet from the queue
        :param packet:
        :return:
        """


        raw_payload = packet.get_payload()

        scapy_packet = IP(raw_payload)


        #TODO : Task 2.2, 3.x ( logica de analiza )
        # Deocamdată, doar afișăm sursa pentru a demonstra că interceptarea funcționează

        if scapy_packet.haslayer(IP):
            ip_src = scapy_packet[IP].src
            print(f"\nInterceptor a capturat un pachet de la {ip_src}")

        # mock verdict -> ACCEPT , pentru a nu bloca reteaua in timpul testului
        packet.accept()


    def start(self):
        """
        Start packet interceptions
        :return:
        """

        try:
            # legam scriptul de coada definita in nftables
            self.nfqueue.bind(self.queue_num, self._process_packet)
            self.is_running = True
            print(f"\nPacket Interceptor starts. Listen on NFQUEUE {self.nfqueue} .. ")

            self.nfqueue.run()

        except KeyboardInterrupt:
            self.stop()

        except Exception as e:
            print(f"\nError in Interceptor {e}")
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


if __name__ == "__main__":
    """testam,"""
    firewall_interceptor = PacketInterceptor(queue_num=1)
    firewall_interceptor.start()
