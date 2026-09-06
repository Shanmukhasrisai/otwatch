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
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id TEXT,
            severity TEXT,
            confidence REAL,
            source TEXT,
            destination TEXT,
            protocol TEXT,
            function TEXT,
            evidence TEXT,
            risk_score REAL,
            mitre_id TEXT,
            status TEXT DEFAULT 'new',
            created_at TEXT
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
        # Support both dict-like and dataclass/object events
        try:
            if isinstance(event, dict):
                timestamp = event.get("timestamp")
                src = event.get("src") or event.get("source")
                dst = event.get("dst") or event.get("destination")
                unit_id = event.get("unit_id")
                function = event.get("function") or event.get("func_code")
                direction = event.get("direction")
                payload_len = event.get("payload_len") or 0
            else:
                timestamp = getattr(event, "timestamp", None)
                src = getattr(event, "source", None)
                dst = getattr(event, "destination", None)
                unit_id = getattr(event, "unit_id", None)
                function = getattr(event, "function", None)
                direction = getattr(event, "direction", None)
                payload_len = getattr(event, "payload_len", 0)
        except Exception:
            # Fallbacks
            timestamp = src = dst = function = direction = None
            unit_id = payload_len = None

        cur.execute(
            "INSERT INTO events (timestamp,src,dst,unit_id,function,direction,payload_len)"
            " VALUES (?,?,?,?,?,?,?)",
            (timestamp, src, dst, unit_id, str(function), direction, payload_len))
        self.conn.commit()

    def get_assets(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM assets")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
