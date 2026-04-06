import sqlite3
from typing import List, Optional

from loguru import logger

from database.setup_db import DB_NAME
from domain.models import RuleModel


class RuleRepository:
    """
    DB repository for Rule table, not-async operation
    """

    @staticmethod
    def get_all() -> List[RuleModel]:
        """
        Return rules from table
        :return:List of rules
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                               SELECT id, ip_src, port, protocol, action, description, enabled
                               FROM Rules
                               ORDER BY id
                               ''')
                return [
                    RuleModel(
                        id=row[0],
                        ip_src=row[1],
                        port=row[2],
                        protocol=row[3].upper() if row[3] else None,
                        action=row[4].upper(),
                        description=row[5],
                        enabled=row[6]
                    )
                    for row in cursor.fetchall()
                ]

        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] get_all error: {e}")
            return []

    @staticmethod
    def get_enabled() -> List[RuleModel]:
        """
        Take from db Rule table only enabled rules, for boot -> kernel and hot-reload
        :return: List of enabled rules
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                               SELECT id, ip_src, port, protocol, action, description, enabled
                               FROM Rules
                               WHERE enabled = 1
                               ORDER BY id
                               ''')
                return [
                    RuleModel(
                        id=row[0],
                        ip_src=row[1],
                        port=row[2],
                        protocol=row[3].upper() if row[3] else None,
                        action=row[4].upper(),
                        description=row[5],
                        enabled=row[6]
                    )
                    for row in cursor.fetchall()
                ]

        except sqlite3.Error as e:
            logger.error(f"[RuleRepository] get_all error: {e}")
            return []

    @staticmethod
    def insert(rule: RuleModel) -> Optional[int]:
        """
        Insert into rule table
        :param rule: rule to be inserted
        :return: rule.id
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO Rules (ip_src, port, protocol, action, description, enabled) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (rule.ip_src, rule.port, rule.protocol, rule.action, rule.description, rule.enabled)
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
        :param rule_id:
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
    def toggle(rule_id: int, enabled: int) -> bool:
        """
        Enable or disable a rule
        :param rule_id: rule_id to toggle
        :param enabled: 1/0
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
