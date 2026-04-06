import sqlite3

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

                cursor.execute("SELECT COUNT(*) FROM Logs")
                stats["total_logs"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM Logs WHERE action_taken = 'ACCEPT'")
                stats["accepted"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM Logs WHERE action_taken = 'DROP'")
                stats["dropped"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM Blacklist")
                stats["banned_ips"] = cursor.fetchone()[0]

        except sqlite3.Error as e:
            logger.error(f"[StatsRepository] error DB: {e}")

        return stats