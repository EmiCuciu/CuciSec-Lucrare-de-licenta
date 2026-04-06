import sqlite3
from typing import Optional, List

from loguru import logger

from database.setup_db import DB_NAME
from domain.models import PacketInfo, LogEntry
from repository.base import AsyncDBWriter


class LogRepository:
    """
    DB repository for Log table
    Writings are async with AsyncDBWriter
    """

    def __init__(self):
        self._writer = AsyncDBWriter()

    def insert(self, packet_info: PacketInfo, action_taken: str, details: str = ""):
        """
        Asynchronous inserting
        :param packet_info: PacketInfo object with packet metadata
        :param action_taken: ACCEPT, DROP or BAN
        :param details: optional string with details about the action ( e.g. reason for BAN )
        :return: None
        """
        sql = """
              INSERT INTO Logs (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
              VALUES (?, ?, ?, ?, ?, ?, ?) \
              """

        params = (
            packet_info.ip_src,
            packet_info.ip_dst,
            packet_info.port_src or 0,
            packet_info.port_dst or 0,
            packet_info.protocol,
            action_taken,
            details
        )

        self._writer.execute(sql, params)

    @staticmethod
    def get_filtered_logs(limit: int = 100,
                          offset: int = 0,
                          protocol: Optional[str] = None,
                          action: Optional[str] = None,
                          ip_src: Optional[str] = None) -> List[LogEntry]:
        """
        Get paginated logs
        """
        # noinspection SqlConstantExpression
        query = "SELECT id, timestamp, ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details FROM Logs WHERE 1=1"
        params = []

        if protocol:
            query += " AND protocol = ?"
            params.append(protocol.upper())

        if action:
            query += " AND action_taken LIKE ?"
            params.append(f"%{action.upper()}%")

        if ip_src:
            query += " AND ip_src = ?"
            params.append(ip_src)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [
                    LogEntry(
                        id=row[0],
                        timestamp=row[1],
                        ip_src=row[2],
                        ip_dst=row[3],
                        port_src=row[4],
                        port_dst=row[5],
                        protocol=row[6],
                        action_taken=row[7],
                        details=row[8] or ""
                    )
                    for row in rows
                ]
        except sqlite3.Error as e:
            logger.error(f"LogRepository.get_filtered_logs error: {e}")
            return []