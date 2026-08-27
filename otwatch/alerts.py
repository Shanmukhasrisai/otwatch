"""Alert engine - flags dangerous Modbus operations."""
from datetime import datetime

DANGEROUS_FUNCTIONS = {5, 6, 15, 16}  # all WRITE operations

class AlertEngine:
    def __init__(self):
        self.alerts = []

    def check(self, event):
        """Return alert dict if event is suspicious, else None."""
        if event["func_code"] in DANGEROUS_FUNCTIONS:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "HIGH",
                "type": "WRITE_OPERATION",
                "message": f"Write command '{event['function']}' sent "
                           f"from {event['src']} to PLC {event['dst']} "
                           f"(unit {event['unit_id']})",
                "event": event,
            }
            self.alerts.append(alert)
            print(f"[!!] ALERT: {alert['message']}")
            return alert
        return None

    def get_alerts(self):
        return self.alerts
