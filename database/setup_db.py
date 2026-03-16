import sqlite3

DB_NAME = "database/CuciSec.db"


def init_db():
    """
    Initialize the database with necessary tables for rules, logs, and blacklist and create indexes for efficient querying on the Logs table.
    :return: None
    """

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS Rules
           (
               id          INTEGER PRIMARY KEY AUTOINCREMENT,
               ip_src      TEXT,
               port        INTEGER,
               protocol    TEXT,
               action      TEXT NOT NULL,
               description TEXT,
               enabled     INTEGER DEFAULT 1
           )'''
    )

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
        '''
        CREATE INDEX IF NOT EXISTS idx_logs_ip_src ON Logs (ip_src)
        '''
    )

    connection.commit()
    connection.close()


if __name__ == "__main__":
    init_db()
