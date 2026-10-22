"""OTWatch Modbus simulator package.

The simulator exposes a lightweight PLC-like register model that can be used to
exercise the OTWatch Modbus parser, detection rules, and API endpoints in a
controlled lab environment.
"""

from __future__ import annotations

import asyncio
import logging
import random
import threading
from typing import Any

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server.sync import StartTcpServer

logger = logging.getLogger("otwatch.simulator")


class ModbusSimulator:
    """A lightweight Modbus/TCP PLC simulator.

    This class creates a simulated PLC register map and keeps a background task
    that continuously changes the apparent process values. This is useful for
    testing:
    - passive protocol inspection
    - write-detection logic
    - threshold-based alerting
    - API telemetry exposure
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5020,
        monitor_mode: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.monitor_mode = monitor_mode

        self._lock = threading.Lock()
        self._server_thread: threading.Thread | None = None
        self._sensor_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

        # Holding register addresses are 0-based internally for Modbus, so:
        # 40001 -> index 0, 40002 -> index 1, 40003 -> index 2
        self._register_count = 100
        self._register_defaults = [0] * self._register_count
        self._register_defaults[0] = 42
        self._register_defaults[1] = 65
        self._register_defaults[2] = 1

        self._slave = ModbusSlaveContext(
            hr=ModbusSequentialDataBlock(0, self._register_defaults)
        )
        self._context = ModbusServerContext(slaves={0x00: self._slave}, single=True)

        self._identity = ModbusDeviceIdentification(
            info_name={
                "VendorName": "OTWatch",
                "ProductCode": "OTW-PLC",
                "VendorUrl": "https://github.com/Shanmukhasrisai/otwatch",
                "ProductName": "OTWatch Simulated PLC",
            }
        )

    @property
    def tank_level(self) -> int:
        """Read the simulated tank level percentage."""
        return self._read_register(40001)

    @tank_level.setter
    def tank_level(self, value: int) -> None:
        self._write_register(40001, value)

    @property
    def pump_speed(self) -> int:
        """Read the simulated pump speed percentage."""
        return self._read_register(40002)

    @pump_speed.setter
    def pump_speed(self, value: int) -> None:
        self._write_register(40002, value)

    @property
    def system_state(self) -> int:
        """Return the current process state ID."""
        return self._read_register(40003)

    @system_state.setter
    def system_state(self, value: int) -> None:
        self._write_register(40003, value)

    def _read_register(self, modbus_address: int) -> int:
        """Read a holding register by Modbus address (e.g., 40001)."""
        index = modbus_address - 40001
        if index < 0 or index >= self._register_count:
            raise ValueError(f"Register address {modbus_address} out of range.")
        with self._lock:
            return int(self._slave.getValues(3, index, 1)[0])

    def _write_register(self, modbus_address: int, value: int) -> None:
        """Write a value to a holding register by Modbus address."""
        index = modbus_address - 40001
        if index < 0 or index >= self._register_count:
            raise ValueError(f"Register address {modbus_address} out of range.")
        with self._lock:
            self._slave.setValues(3, index, [int(value)])

    async def start(self) -> None:
        """Start the Modbus server and background telemetry drift task."""
        if self._sensor_task is not None and not self._sensor_task.done():
            logger.warning("Sensor loop already running; skipping duplicate start.")
            return

        self._stop_event.clear()

        self._server_thread = threading.Thread(
            target=self._run_server,
            daemon=True,
            name="otwatch-modbus-server",
        )
        self._server_thread.start()

        self._sensor_task = asyncio.create_task(self._sensor_loop())
        logger.info(
            "Modbus PLC simulator started on %s:%s in monitor mode=%s",
            self.host,
            self.port,
            self.monitor_mode,
        )

    async def stop(self) -> None:
        """Stop the sensor drift loop and server."""
        self._stop_event.set()

        if self._sensor_task is not None:
            self._sensor_task.cancel()
            try:
                await self._sensor_task
            except asyncio.CancelledError:
                pass
            self._sensor_task = None

        logger.info("Modbus PLC simulator stopped.")

    def _run_server(self) -> None:
        """Blocking Modbus/TCP server entry point.

        This method runs in a background thread so the async telemetry loop can
        continue operating without blocking the event loop.
        """
        logger.info("Starting Modbus/TCP server thread on %s:%s", self.host, self.port)
        StartTcpServer(
            context=self._context,
            identity=self._identity,
            address=(self.host, self.port),
            allow_reuse_address=True,
        )

    async def _sensor_loop(self) -> None:
        """Update tank and pump values to mimic natural industrial fluctuation.

        The loop is intentionally simple but realistic for a small process:
        - tank level drifts gradually
        - pump speed reacts to the level
        - system state toggles between running and alarm states under stress
        """
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(2.0)

                current_level = self.tank_level
                current_speed = self.pump_speed
                current_state = self.system_state

                level_delta = random.randint(-2, 3)
                speed_delta = random.randint(-4, 4)

                next_level = max(0, min(100, current_level + level_delta))
                next_speed = max(0, min(100, current_speed + speed_delta))

                if next_level > 88:
                    next_speed = min(100, next_speed + 5)

                if current_state == 2:
                    next_level = max(0, min(100, next_level + 1))
                    next_speed = max(0, min(100, next_speed + 2))

                if random.random() < 0.08:
                    next_state = 2 if current_state != 2 else 1
                else:
                    next_state = 1 if current_state in (0, 1) else 2

                self.tank_level = next_level
                self.pump_speed = next_speed
                self.system_state = next_state

                logger.debug(
                    "Telemetry update: tank=%s%% pump=%s%% state=%s",
                    self.tank_level,
                    self.pump_speed,
                    self.system_state,
                )
            except asyncio.CancelledError:
                logger.info("Sensor loop cancelled.")
                break
            except Exception as exc:  # pragma: no cover
                logger.exception("Unexpected simulator error: %s", exc)
                break

    def snapshot(self) -> dict[str, Any]:
        """Return the current PLC state for API or logging use."""
        return {
            "device_id": "PLC-01",
            "monitor_mode": self.monitor_mode,
            "registers": {
                "40001": self.tank_level,
                "40002": self.pump_speed,
                "40003": self.system_state,
            },
        }


async def main() -> None:
    """Run the simulator as a standalone process."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    simulator = ModbusSimulator()
    await simulator.start()

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt; shutting down simulator.")
    finally:
        await simulator.stop()


if __name__ == "__main__":
    asyncio.run(main())


"""OTWatch Modbus simulator package.

This package exposes a lightweight PLC-like register model that can be used to
exercise the OTWatch Modbus parser, detection rules, and API endpoints in a
controlled lab environment.
"""

__all__ = ["ModbusSimulator"]
