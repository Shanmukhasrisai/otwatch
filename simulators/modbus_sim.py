"""Fake PLC simulator - test OTWatch without real hardware."""
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext)

print("[*] Starting fake PLC simulator on port 502...")
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 100))
StartTcpServer(context=ModbusServerContext(slaves=store, single=True),
               address=("0.0.0.0", 502))
