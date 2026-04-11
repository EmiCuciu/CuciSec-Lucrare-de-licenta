from loguru import logger

class StatsService:
    """
    Class for statistics service
    """

    @staticmethod
    def parse_flood_counters(nft_json: dict) -> dict:
        """
        Function that parse nft-json contors to counters for visualize
        :param nft_json: `nft -j list ruleset` command
        :return: counters
        """
        counters = {
            "icmp_flood_dropped": 0,
            "tcp_syn_flood_dropped": 0,
            "udp_flood_dropped": 0,
            "blacklist_dropped": 0,
            "honeyport_hits": 0
        }

        try:
            nftables = nft_json.get("nftables", [])

            for item in nftables:
                rule = item.get("rule")
                if not rule:
                    continue

                comment = rule.get("comment")   # "tcp_syn_flood", "icmp_flood", "udp_flood"
                if not comment:
                    continue

                # watch for contor in rule expressions
                expr_list = rule.get("expr", [])

                packets = 0
                for expr in expr_list:
                    if "counter" in expr:
                        packets = expr["counter"].get("packets", 0)
                        break

                if packets == 0:
                    continue

                if comment == "icmp_flood":
                    counters["icmp_flood_dropped"] += packets
                elif comment == "tcp_syn_flood":
                    counters["tcp_syn_flood_dropped"] += packets
                elif comment == "udp_flood":
                    counters["udp_flood_dropped"] += packets
                elif comment == "blacklist_drop":
                    counters["blacklist_dropped"] += packets
                elif comment == "honeyport_drop":
                    counters["honeyport_hits"] += packets

        except Exception as e:
            logger.exception(f"[Stats Service] Error while parsing nft-json: {e}")

        return counters