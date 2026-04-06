import queue
import sqlite3
import threading

from loguru import logger

from database.setup_db import DB_NAME


class AsyncDBWriter:
    """
    Pattern: Producer-Consumer
        P: any repo - calls execute()
        C: writing thread - calls _run()
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True

        self._queue = queue.Queue(maxsize=10000)
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()
        logger.info("[AsyncDBWriter] thread started.")

    def _run(self):
        """
        Thread for writing
        Only one connection
        :return: None
        """

        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        cursor = conn.cursor()

        while True:
            item = self._queue.get()

            # sentinel value for shutdown
            if item is None:
                self._queue.task_done()
                break

            sql, params = item

            try:
                cursor.execute(sql, params)
                conn.commit()
            except Exception as e:
                logger.error(f"[AsyncDBWriter] error: {e}")

            finally:
                self._queue.task_done()

        conn.close()
        logger.info("[AsyncDBWriter]: stopped, connection closed")

    def execute(self, sql: str, params: tuple):
        """
        Adds one writing operation in queue (non-blocking)
        If queue is full, operation is ignored
        :param sql: SQL command
        :param params: command Parameters
        :return: None
        """
        try:
            self._queue.put_nowait((sql, params))
        except queue.Full:
            logger.error("[AsyncDBWriter]: queue FULL - dropping write operation")

    def stop(self):
        """
        Stops the thread - waits for the queue to empty
        :return: None
        """
        self._queue.put(None)
        self._worker.join()
