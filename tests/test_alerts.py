from otwatch.alerts import AlertEngine
from otwatch.events import OTEvent
import time


def test_alerts_write_to_db():
    ae = AlertEngine(db=":memory:")
    # craft a write event
    ev = OTEvent(
        timestamp=time.time(),
        source="10.0.0.5",
        destination="10.0.0.10",
        source_port=33333,
        destination_port=502,
        protocol="modbus",
        asset_id=None,
        zone=None,
        direction="request",
        operation="write",
        function=6,
        object=None,
        value=1234,
        session="10.0.0.5:33333->10.0.0.10:502",
        confidence=1.0,
        severity="HIGH",
        detection_id=None,
    )

    alert = ae.check(ev)
    assert alert is not None
    all_alerts = ae.get_alerts()
    assert len(all_alerts) == 1
    a = all_alerts[0]
    assert a["severity"] == "HIGH"
    assert a["function"] == str(6)
