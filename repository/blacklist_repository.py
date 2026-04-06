import sqlite3
from typing import List

from loguru import logger

from database.setup_db import DB_NAME
from domain.models import BlacklistEntry
from repository.base import AsyncDBWriter


class BlacklistRepository:
    """
    DB repository for Blacklist Table
    Writings are async with AsyncDBWriter,
    Readings are sync with short connections
    """

    def __init__(self):
        self._writer = AsyncDBWriter()

    def add(self, entry: BlacklistEntry):
        """
        Insert ip into Blacklist table
        :param entry: Blacklist entity
        :return: None
        """

        sql = "INSERT OR IGNORE INTO Blacklist (ip, reason) VALUES (?, ?)"
        self._writer.execute(sql, (entry.ip, entry.reason))

    @staticmethod
    def get_all() -> List[BlacklistEntry]:
        """
        Reading from Blacklist table
        :return: List of banned IPs
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT id, ip, reason, timestamp FROM Blacklist "
                               "ORDER BY timestamp DESC ")
                return [
                    BlacklistEntry(id=row[0],
                                   ip=row[1],
                                   reason=row[2],
                                   timestamp=row[3])
                    for row in cursor.fetchall()
                ]
        except sqlite3.Error as e:
            logger.error(f"[BlacklistRepository] get_all error: {e}")
            return []

    def get_all_ips(self) -> List[str]:
        """
        Only ips for kernel side blacklist
        :return: List of ips
        """
        return [entry.ip for entry in self.get_all()]

    @staticmethod
    def delete(ip: str):
        """
        Delete an ip from Blacklist
        :param ip: ip to delete from blacklist
        :return: None
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("DELETE FROM Blacklist WHERE ip = ?", (ip,))
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"[BlacklistRepository] delete error: {e}")
