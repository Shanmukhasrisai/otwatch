"""ICS security rule evaluation for OTWatch.

This module contains the detection logic used to evaluate Modbus/TCP traffic and
flag suspicious or unsafe conditions. The rules are written to be simple,
auditable, and easy to map to ICS-specific adversary behaviors and ATT&CK
mitigations.

Industrial terms used here:
- "Monitor Mode" refers to an environment where write operations are observed
  but not permitted to affect device state.
- "Holding Register" is the PLC memory area used to store process values such
  as tank level, pump speed, and system mode.
- "Function Code (FC)" identifies the Modbus command class, such as write coil
  (FC05), write single register (FC06), write multiple coils (FC15), or write
  multiple registers (FC16).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

logger = logging.getLogger("otwatch.rules")

WRITE_FUNCTION_CODES = {5, 6, 15, 16}

MITRE_ICS_ATTACKS = {
    "T0836": "Modify Parameter",
    "T0809": "Manipulation of Control",
    "T0863": "Spearphishing Attachment",
}

DEFAULT_THRESHOLDS = {
    "tank_level_max_percent": 90,
    "pump_speed_max_percent": 95,
    "system_state_allowed": {0, 1, 2},
}


@dataclass(slots=True)
class ModbusEvent:
    """Structured representation of a Modbus message for rule evaluation."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: str = "PLC-01"
    function_code: int = 0
    register_address: int | None = None
    value: int | list[int] | None = None
    operation: str = "read"
    mode: str = "Monitor Mode"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModbusRuleViolation:
    """Single rule trigger generated after evaluating a Modbus event."""

    rule_id: str
    severity: str
    message: str
    mitre_attack_ids: list[str]
    event: ModbusEvent

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["event"] = self.event.to_dict()
        return data


def _coerce_int(value: Any) -> int:
    """Safely coerce Modbus values to an integer."""
    if isinstance(value, list):
        if not value:
            raise ValueError("Empty Modbus list value cannot be converted to int.")
        return int(value[0])
    if isinstance(value, tuple):
        if not value:
            raise ValueError("Empty Modbus tuple value cannot be converted to int.")
        return int(value[0])
    return int(value)


def _register_name(register_address: int | None) -> str:
    """Translate a register address to a readable tag name for reporting."""
    if register_address == 40001:
        return "Tank Level"
    if register_address == 40002:
        return "Pump Speed"
    if register_address == 40003:
        return "System State"
    return f"Register {register_address}" if register_address is not None else "Unknown Register"


def evaluate_modbus_event(
    event: ModbusEvent,
    monitor_mode: bool = True,
    thresholds: Mapping[str, Any] | None = None,
) -> list[ModbusRuleViolation]:
    """Evaluate one Modbus event against OT safety and security rules.

    Rules implemented:
    1. If a write operation occurs while the PLC is in Monitor Mode, flag it.
    2. If a process value exceeds configured safety thresholds, raise an alert.
    3. Map each alert to relevant MITRE ATT&CK for ICS identifiers.
    """

    effective_thresholds = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        effective_thresholds.update(thresholds)

    violations: list[ModbusRuleViolation] = []

    if event.function_code in WRITE_FUNCTION_CODES and monitor_mode:
        violations.append(
            ModbusRuleViolation(
                rule_id="WRITE_IN_MONITOR_MODE",
                severity="high",
                message=(
                    f"Write operation on {event.device_id} was observed in Monitor Mode "
                    f"(FC{event.function_code}). This may indicate unauthorized configuration "
                    "change or an attempt to modify device state without approval."
                ),
                mitre_attack_ids=["T0836"],
                event=event,
            )
        )

    if event.register_address is not None:
        value = event.value
        if value is None:
            return violations

        try:
            numeric_value = _coerce_int(value)
        except (TypeError, ValueError):
            return violations

        if event.register_address == 40001:
            threshold = effective_thresholds["tank_level_max_percent"]
            if numeric_value > threshold:
                violations.append(
                    ModbusRuleViolation(
                        rule_id="TANK_LEVEL_EXCEEDED_LIMIT",
                        severity="critical",
                        message=(
                            f"{_register_name(event.register_address)} reached {numeric_value}% "
                            f"which exceeds the operational maximum of {threshold}%."
                        ),
                        mitre_attack_ids=["T0836"],
                        event=event,
                    )
                )

        if event.register_address == 40002:
            threshold = effective_thresholds["pump_speed_max_percent"]
            if numeric_value > threshold:
                violations.append(
                    ModbusRuleViolation(
                        rule_id="PUMP_SPEED_EXCEEDED_LIMIT",
                        severity="high",
                        message=(
                            f"{_register_name(event.register_address)} reached {numeric_value}% "
                            f"which exceeds the safe operating limit of {threshold}%."
                        ),
                        mitre_attack_ids=["T0836"],
                        event=event,
                    )
                )

        if event.register_address == 40003:
            allowed_states = set(effective_thresholds["system_state_allowed"])
            if numeric_value not in allowed_states:
                violations.append(
                    ModbusRuleViolation(
                        rule_id="INVALID_SYSTEM_STATE",
                        severity="medium",
                        message=(
                            f"{_register_name(event.register_address)} was set to {numeric_value}, "
                            f"which is outside the expected set of {sorted(allowed_states)}."
                        ),
                        mitre_attack_ids=["T0809"],
                        event=event,
                    )
                )

    return violations


class RuleEngine:
    """Utility to evaluate many Modbus events and retain alert history."""

    def __init__(
        self,
        monitor_mode: bool = True,
        thresholds: Mapping[str, Any] | None = None,
    ) -> None:
        self.monitor_mode = monitor_mode
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            self.thresholds.update(thresholds)
        self.alerts: list[ModbusRuleViolation] = []

    def evaluate(self, event: ModbusEvent) -> list[ModbusRuleViolation]:
        """Evaluate one Modbus event and append any violations to the alert log."""
        violations = evaluate_modbus_event(
            event=event,
            monitor_mode=self.monitor_mode,
            thresholds=self.thresholds,
        )
        self.alerts.extend(violations)
        for violation in violations:
            logger.warning(
                "Rule trigger: %s | %s | MITRE=%s",
                violation.rule_id,
                violation.message,
                ", ".join(violation.mitre_attack_ids),
            )
        return violations

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return stored rule-triggering events in JSON-serializable form."""
        return [alert.to_dict() for alert in self.alerts]


__all__ = [
    "DEFAULT_THRESHOLDS",
    "MITRE_ICS_ATTACKS",
    "ModbusEvent",
    "ModbusRuleViolation",
    "RuleEngine",
    "evaluate_modbus_event",
]
