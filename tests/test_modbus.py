import struct
import time
from otwatch.protocols.registry import get_parser_for_port
from otwatch.events import OTEvent

from otwatch.protocols.modbus import ModbusParser

# Tests build golden Modbus frames and assert parser outputs


def build_mbap(txn=1, proto=0, unit=1, pdu=b""):
    # length = unit(1) + len(pdu)
    length = 1 + len(pdu)
    return struct.pack(
        ">HHHB", txn, proto, length, unit
    ) + pdu


def test_modbus_read_request():
    # FC3 read holding registers request: func(1) + start(2) + qty(2)
    pdu = bytes([3, 0x00, 0x01, 0x00, 0x02])
    frame = build_mbap(txn=10, pdu=pdu, unit=2)
    parser = get_parser_for_port(502)
    assert parser is not None
    events = parser.parse("10.0.0.1", "10.0.0.2", 12345, 502, frame, timestamp=time.time())
    assert len(events) == 1
    ev = events[0]
    assert ev.direction == "request"
    assert ev.operation == "read"
    assert ev.function == 3
    assert ev.protocol == "modbus"


def test_modbus_read_response():
    # response typically has func + byte count + data
    pdu = bytes([3, 4, 0x00, 0x01, 0x00, 0x02])
    frame = build_mbap(txn=11, pdu=pdu, unit=2)
    parser = get_parser_for_port(502)
    events = parser.parse("10.0.0.2", "10.0.0.1", 502, 12345, frame, timestamp=time.time())
    assert len(events) == 1
    ev = events[0]
    assert ev.direction == "response"
    assert ev.operation == "read"
    assert ev.function == 3


def test_modbus_write_single():
    # FC6 write single register request: func + addr(2) + value(2)
    pdu = bytes([6, 0x00, 0x02, 0x04, 0xD2])
    frame = build_mbap(txn=20, pdu=pdu, unit=1)
    parser = get_parser_for_port(502)
    events = parser.parse("192.168.1.10", "192.168.1.20", 44444, 502, frame, timestamp=time.time())
    ev = events[0]
    assert ev.operation == "write"
    assert ev.function == 6


def test_modbus_write_multiple():
    # FC16 write multiple registers request: func + addr + qty + bytecount + data
    pdu = bytes([16, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02])
    frame = build_mbap(txn=21, pdu=pdu, unit=1)
    parser = get_parser_for_port(502)
    events = parser.parse("192.168.1.10", "192.168.1.20", 55555, 502, frame, timestamp=time.time())
    ev = events[0]
    assert ev.operation == "write"
    assert ev.function == 16


def test_modbus_malformed_short():
    # too short to contain MBAP
    frame = b"\x00\x01\x00"
    parser = get_parser_for_port(502)
    events = parser.parse("1.1.1.1", "2.2.2.2", 1234, 502, frame, timestamp=time.time())
    assert events == []
