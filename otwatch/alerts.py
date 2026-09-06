"""Alert engine - flags dangerous Modbus operations and persists alerts to SQLite."""
from datetime import datetime
import sqlite3
import json
import uuid
from typing import Any

DANGEROUS_FUNCTIONS = {5, 6, 15, 16}  # all WRITE operations

class AlertEngine:
    def __init__(self, db: str = "data/ot_inventory.db"):
        import os
        os.makedirs("data", exist_ok=True)
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.executescript("""
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

    def check(self, event: Any):
        """Return alert dict if event is suspicious, else None.
        Accepts either dict-like events or dataclass objects with attributes.
        """
        # extract function code
        fn = None
        try:
            if isinstance(event, dict):
                fn = event.get("func_code") or event.get("function")
            else:
                fn = getattr(event, "function", None)
        except Exception:
            fn = None

        if fn in DANGEROUS_FUNCTIONS:
            detection_id = str(uuid.uuid4())
            severity = "HIGH"
            confidence = 1.0
            source = getattr(event, "source", event.get("src") if isinstance(event, dict) else None)
            destination = getattr(event, "destination", event.get("dst") if isinstance(event, dict) else None)
            protocol = getattr(event, "protocol", "modbus")

            evidence = json.dumps({
                "event": event.__dict__ if not isinstance(event, dict) else event
            })

            risk_score = 9.0
            created_at = datetime.utcnow().isoformat()

            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO alerts (detection_id,severity,confidence,source,destination,protocol,function,evidence,risk_score,created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (detection_id, severity, confidence, source, destination, str(fn), evidence, risk_score, created_at)
            )
            self.conn.commit()

            alert = {
                "detection_id": detection_id,
                "severity": severity,
                "confidence": confidence,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "function": fn,
                "evidence": json.loads(evidence),
                "risk_score": risk_score,
                "created_at": created_at,
            }
            print(f"[!!] ALERT: write command from {source} to {destination} (fn={fn})")
            return alert
        return None

    def get_alerts(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY id DESC")
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        results = []
        for r in rows:
            d = dict(zip(cols, r))
            # try to parse evidence JSON
            try:
                d["evidence"] = json.loads(d.get("evidence") or "null")
            except Exception:
                pass
            results.append(d)
        return results
