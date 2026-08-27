"""Asset inventory database (SQLite)."""
import sqlite3
import time

class Inventory:
    def __init__(self, db="data/ot_inventory.db"):
        import os
        os.makedirs("data", exist_ok=True)
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            role TEXT,
            protocol TEXT,
            first_seen TEXT,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, src TEXT, dst TEXT, unit_id INT,
            function TEXT, direction TEXT, payload_len INT
        );
        """)
        self.conn.commit()

    def register(self, ip, role, protocol):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        cur = self.conn.cursor()
        cur.execute("SELECT ip FROM assets WHERE ip=?", (ip,))
        if cur.fetchone():
            cur.execute("UPDATE assets SET last_seen=? WHERE ip=?", (now, ip))
        else:
            cur.execute(
                "INSERT INTO assets VALUES (?,?,?,?,?)",
                (ip, role, protocol, now, now))
            print(f"[+] NEW ASSET DISCOVERED: {ip} ({role}, {protocol})")
        self.conn.commit()

    def log_event(self, event):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (timestamp,src,dst,unit_id,function,direction,payload_len)"
            " VALUES (?,?,?,?,?,?,?)",
            (event["timestamp"], event["src"], event["dst"],
             event["unit_id"], event["function"],
             event["direction"], event["payload_len"]))
        self.conn.commit()

    def get_assets(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM assets")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
