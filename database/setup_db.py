import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(BASE_DIR, "database", "CuciSec.db")


def init_db():
    """
    Initialize the database with necessary tables for rules, logs, and blacklist
    and create indexes for efficient querying on the Logs table.
    :return: None
    """

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    # enables reading and writing simultaneously
    cursor.execute('PRAGMA journal_mode=WAL;')

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS Rules
           (
               id          INTEGER PRIMARY KEY AUTOINCREMENT,
               ip_src      TEXT,
               ip_dst      TEXT,
               port        INTEGER,
               protocol    TEXT,
               action      TEXT NOT NULL,
               description TEXT,
               enabled     INTEGER DEFAULT 1,
               zone        TEXT    DEFAULT 'WAN'
           )'''
    )

    # Migration: add ip_dst column if DB was created before this version
    try:
        cursor.execute("ALTER TABLE Rules ADD COLUMN ip_dst TEXT")
    except Exception:
        pass  # column already exists

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS Logs
           (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
               ip_src       TEXT,
               ip_dst       TEXT,
               port_src     INTEGER,
               port_dst     INTEGER,
               protocol     TEXT,
               action_taken TEXT,
               details      TEXT
           )'''
    )

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS Blacklist
           (
               id        INTEGER PRIMARY KEY AUTOINCREMENT,
               ip        TEXT UNIQUE NOT NULL,
               reason    TEXT,
               timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
           )'''
    )

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS KernelCounters
           (
               id           INTEGER PRIMARY KEY DEFAULT 1,
               tcp_syn      INTEGER DEFAULT 0,
               icmp         INTEGER DEFAULT 0,
               udp          INTEGER DEFAULT 0,
               blacklist    INTEGER DEFAULT 0,
               honeyport    INTEGER DEFAULT 0,
               last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
           )'''
    )
    cursor.execute('INSERT OR IGNORE INTO KernelCounters (id) VALUES (1)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip_src ON Logs (ip_src)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON Logs (timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_protocol ON Logs (protocol)')

    connection.commit()
    connection.close()

