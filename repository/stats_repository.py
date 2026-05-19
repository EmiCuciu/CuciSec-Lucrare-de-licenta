import sqlite3
from typing import List

from loguru import logger

from database.setup_db import DB_NAME


class StatsRepository:
    """
    General statistics from DB
    """

    @staticmethod
    def get_db_stats() -> dict:
        """
        return general stats from repo
        :return: dictionary with statistic
        """
        stats = {
            "total_logs": 0,
            "accepted": 0,
            "dropped": 0,
            "banned_ips": 0
        }
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                               SELECT COUNT(*)                                                           as total,
                                        SUM(CASE WHEN action_taken LIKE 'ACCEPT%' THEN 1 ELSE 0 END)     as accepted,
                                        SUM(CASE WHEN action_taken NOT LIKE 'ACCEPT%' THEN 1 ELSE 0 END) as dropped
                               FROM Logs
                               """)
                row = cursor.fetchone()
                stats["total_logs"] = row[0]
                stats["accepted"] = row[1]
                stats["dropped"] = row[2]

                cursor.execute("SELECT COUNT(*) FROM Blacklist")
                stats["banned_ips"] = cursor.fetchone()[0]

        except sqlite3.Error as e:
            logger.error(f"[StatsRepository] error DB: {e}")

        return stats

    @staticmethod
    def get_kernel_counters() -> dict:
        """
        Return cumulative kernel drop counters from DB.
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT tcp_syn, icmp, udp, blacklist, honeyport FROM KernelCounters WHERE id=1")
                row = cursor.fetchone()
                if row:
                    return {
                        "tcp_syn_flood_dropped": row[0],
                        "icmp_flood_dropped":    row[1],
                        "udp_flood_dropped":     row[2],
                        "blacklist_dropped":     row[3],
                        "honeyport_hits":        row[4],
                    }
        except sqlite3.Error as e:
            logger.error(f"[StatsRepository] get_kernel_counters error: {e}")
        return {"tcp_syn_flood_dropped": 0, "icmp_flood_dropped": 0,
                "udp_flood_dropped": 0, "blacklist_dropped": 0, "honeyport_hits": 0}

    @staticmethod
    def accumulate_kernel_counters(delta: dict):
        """
        Add delta values to the single cumulative KernelCounters row.
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """UPDATE KernelCounters
                       SET tcp_syn      = tcp_syn   + ?,
                           icmp         = icmp      + ?,
                           udp          = udp       + ?,
                           blacklist    = blacklist + ?,
                           honeyport    = honeyport + ?,
                           last_updated = CURRENT_TIMESTAMP
                       WHERE id = 1""",
                    (
                        delta.get("tcp_syn_flood_dropped", 0),
                        delta.get("icmp_flood_dropped",    0),
                        delta.get("udp_flood_dropped",     0),
                        delta.get("blacklist_dropped",     0),
                        delta.get("honeyport_hits",        0),
                    )
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"[StatsRepository] accumulate_kernel_counters error: {e}")

    @staticmethod
    def get_recent_bans(limit: int = 5) -> List[dict]:
        """
        return last banned ip with timestamp
        :param limit: integer
        :return: list of banned ips
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, reason, timestamp FROM Blacklist "
                               "ORDER BY timestamp DESC LIMIT ?", (limit,))
                return [
                    {"ip": row[0],
                     "reason": row[1],
                     "timestamp": row[2]}
                    for row in cursor.fetchall()
                ]
        except sqlite3.Error as e:
            logger.error(f"[StatsRepository] get_recent_bans error: {e}")
            return []