import sqlite3

from database.setup_db import DB_NAME


class RuleEngine:
    def __init__(self, db_path=DB_NAME):
        self.db_path = db_path
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """
        Loads rules from db, one time, and stores them into RAM. (Prevents bottleneck)
        :return: NONE
        """
        connection = None
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()

            cursor.execute("SELECT ip_src, port, protocol, action FROM Rules WHERE enabled = 1")
            rows = cursor.fetchall()

            self.rules = []
            for row in rows:
                self.rules.append({
                    "ip_src": row[0],
                    "port": row[1],
                    "protocol": row[2].upper() if row[2] else None,
                    "action": row[3].upper() if row[3] else "DROP"
                })

            print(f"RuleEngine: {len(self.rules)} rules loaded in RAM")

        except Exception as e:
            print(f"RuleEngine error: {e}")

        finally:
            if connection:
                connection.close()

    def evaluate(self, packet_data: dict):
        """
        Compares the current packet with in-memory rules
        :param packet_data:
        :return: 'ACCEPT' , 'DROP', or 'None'
        """
        if not packet_data:
            return None

        for rule in self.rules:

            ip_match = True
            if rule["ip_src"] is not None and rule["ip_src"] != packet_data.get("ip_src"):
                ip_match = False

            protocol_match = True
            if rule["protocol"] is not None and rule["protocol"] != packet_data.get("protocol"):
                protocol_match = False

            port_match = True
            if rule["port"] is not None:
                rule_port = int(rule["port"])
                if rule_port != packet_data.get("port_dst") and rule_port != packet_data.get("port_src"):
                    port_match = False

            # if the packet matches all rules metadatas
            if ip_match and protocol_match and port_match:
                return rule["action"]

        # if no rules matched
        return None
