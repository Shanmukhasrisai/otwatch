"""REST API + dashboard backend."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from otwatch.inventory import Inventory
from otwatch.alerts import AlertEngine

app = FastAPI(title="OTWatch API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

inv = Inventory()
alert_engine = AlertEngine()

@app.get("/")
def home():
    return {"tool": "OTWatch", "status": "running", "version": "0.1.0"}

@app.get("/api/assets")
def list_assets():
    """All discovered OT assets."""
    return inv.get_assets()

@app.get("/api/events")
def recent_events(limit: int = 100):
    """Recent Modbus events."""
    cur = inv.conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

@app.get("/api/alerts")
def get_alerts():
    """Security alerts (dangerous write operations)."""
    return alert_engine.get_alerts()
