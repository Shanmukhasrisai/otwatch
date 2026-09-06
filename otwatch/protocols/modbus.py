"""Modbus TCP protocol parser updated to the new ProtocolParser interface."""
import struct
import time
from datetime import datetime
from typing import List, Optional
from otwatch.events import OTEvent
from otwatch.protocols.registry import register_parser

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}

DANGEROUS_FUNCTIONS = {5, 6, 15, 16}


class ModbusParser:
    name = "modbus"
    ports = (502,)

    def matches(self, payload: bytes) -> bool:
        return len(payload) >= 8 and struct.unpack_from(">HHHB", payload, 0)[1] == 0

    def parse(self, src: str, dst: str, sport: int, dport: int, payload: bytes, timestamp: float = None) -> List[OTEvent]:
        if timestamp is None:
            timestamp = time.time()
        events: List[OTEvent] = []
        if len(payload) < 8:
            return events

        # MBAP header: txn_id(2), proto_id(2), length(2), unit_id(1)
        try:
            txn_id, proto_id, length, unit_id = struct.unpack_from(">HHHB", payload, 0)
        except struct.error:
            return events

        func_code = payload[7]
        if proto_id != 0:
            return events

        is_request = dport == 502
        direction = "request" if is_request else "response"
        operation = "write" if func_code in DANGEROUS_FUNCTIONS else "read"

        # object and value parsing are simplified for passive parsing
        obj = None
        val = None
        try:
            fn_name = FUNCTION_NAMES.get(func_code, f"Unknown({func_code})")
            # build session key
            session = f"{src}:{sport}->{dst}:{dport}"

            ev = OTEvent(
                timestamp=timestamp,
                source=src,
                destination=dst,
                source_port=sport,
                destination_port=dport,
                protocol="modbus",
                asset_id=None,
                zone=None,
                direction=direction,
                operation=operation,
                function=func_code,
                object=obj,
                value=val,
                session=session,
                confidence=1.0,
                severity=("HIGH" if operation == "write" else None),
                detection_id=None,
            )
            events.append(ev)
        except Exception:
            return events

        return events


# Provide a backwards-compatible function for existing imports
def parse_modbus(src, dst, sport, dport, payload):
    p = ModbusParser()
    res = p.parse(src, dst, sport, dport, payload, timestamp=time.time())
    return res[0] if res else None


# register the parser with the registry
register_parser(ModbusParser)
