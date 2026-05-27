import sqlite3
from typing import List, Optional

from loguru import logger

from database.setup_db import DB_NAME
from domain.models import RuleModel

_SELECT = """
    SELECT id, ip_src, ip_dst, port, protocol,
           action, description, enabled, zone
    FROM Rules
"""


def _row_to_rule(row) -> RuleModel:
    return RuleModel(
        id=row[0],
        ip_src=row[1],
        ip_dst=row[2],
        port=row[3],
        protocol=row[4].upper() if row[4] else None,
        action=row[5].upper(),
        description=row[6],
        enabled=row[7],
        zone=row[8],
    )


class RuleRepository:
    """
    DB repository for Rule table, not-async operation
    """

    @staticmethod
    def get_all() -> List[RuleModel]:
        """
        Return all rules from table
        :return: List of rules
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(_SELECT + "ORDER BY id")
                return [_row_to_rule(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] get_all error: {e}")
            return []

    @staticmethod
    def get_enabled() -> List[RuleModel]:
        """
        Return only enabled rules, used for boot and hot-reload
        :return: List of enabled rules
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(_SELECT + "WHERE enabled = 1 ORDER BY id")
                return [_row_to_rule(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] get_enabled error: {e}")
            return []

    @staticmethod
    def insert(rule: RuleModel) -> Optional[int]:
        """
        Insert a rule into the table
        :param rule: rule to be inserted
        :return: rule.id
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO Rules (ip_src, ip_dst, port, protocol, action, description, enabled, zone) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (rule.ip_src, rule.ip_dst, rule.port, rule.protocol,
                     rule.action, rule.description, rule.enabled, rule.zone)
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] insert error: {e}")
            return None

    @staticmethod
    def delete(rule_id: int) -> bool:
        """
        Delete a rule by id
        :param rule_id: id of rule to delete
        :return: boolean
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM Rules WHERE id = ?", (rule_id,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] delete error: {e}")
            return False

    @staticmethod
    def update(rule_id: int, rule: RuleModel) -> bool:
        """
        Update all fields of a rule by id
        :param rule_id: rule to update
        :param rule: new rule data
        :return: boolean
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE Rules SET ip_src=?, ip_dst=?, port=?, protocol=?, "
                    "action=?, description=?, enabled=?, zone=? WHERE id=?",
                    (rule.ip_src, rule.ip_dst, rule.port, rule.protocol,
                     rule.action, rule.description, rule.enabled, rule.zone, rule_id)
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] update error: {e}")
            return False

    @staticmethod
    def toggle(rule_id: int, enabled: int) -> bool:
        """
        Enable or disable a rule
        :param rule_id: rule to toggle
        :param enabled: 1 or 0
        :return: boolean
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE Rules SET enabled = ? WHERE id = ?", (enabled, rule_id))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] toggle error: {e}")
            return False