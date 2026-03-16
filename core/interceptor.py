from netfilterqueue import NetfilterQueue

from analyzer import PacketAnalyzer


class PacketInterceptor:
    """
    Class responsible with packet takeover from NFQUEUE, using NetFilterQueue, and sending them to UserSpace
    """

    def __init__(self, queue_num: int = 1):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False
        self.analyzer = PacketAnalyzer()

    def _process_packet(self, packet):
        """
        Callback funtion for every packet from the queue
        turns raw packet into scapy packet and analyze it
        :param packet: packet from NFQUEUE
        :return: None
        :note: verdict (accept, drop, modify) will be decided based on the analysis logic implemented in this function
        """

        raw_payload = packet.get_payload()

        packet_data = self.analyzer.analyze(raw_payload)

        # show what is in packet_data
        if packet_data:
            print(f"Packet: Protocol: {packet_data['protocol']} | IP_SRC: {packet_data['ip_src']} : PORT_SRC: {packet_data['port_src']} | "
                  f"IP_DST: {packet_data['ip_dst']} : PORT_DST: {packet_data['port_dst']}")

            if packet_data["payload"]:
                print(f"Payload: {packet_data['payload']} ...")

        # mock verdict -> ACCEPT , pentru a nu bloca reteaua in timpul testului
        packet.accept()


    def start(self):
        """
        Start packet interceptions
        bind NFQUEUE to the callback function that will process each packet
        :return:
        """

        try:

            self.nfqueue.bind(self.queue_num, self._process_packet)
            self.is_running = True
            print(f"\nPacket Interceptor starts. Listen on NFQUEUE {self.queue_num} .. ")

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


if __name__ == "__main__":
    firewall_interceptor = PacketInterceptor(queue_num=1)
    firewall_interceptor.start()