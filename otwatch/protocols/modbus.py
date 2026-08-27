"""Modbus TCP protocol parser."""
import struct
from datetime import datetime

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

def parse_modbus(src, dst, sport, dport, payload):
    """Parse MBAP header + PDU from raw payload. Returns dict or None."""
    if len(payload) < 8:
        return None

    txn_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
    func_code = payload[7]

    if proto_id != 0:
        return None  # not valid Modbus

    is_request = dport == 502
    fn_name = FUNCTION_NAMES.get(func_code, f"Unknown({func_code})")

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "src": src,
        "dst": dst,
        "unit_id": unit_id,
        "function": fn_name,
        "func_code": func_code,
        "direction": "request" if is_request else "response",
        "payload_len": len(payload),
    }
