"""OTWatch core package.

This package contains the security rule engine and protocol analysis utilities for
industrial control system (ICS) telemetry and Modbus/TCP traffic inspection.
"""

from .rules import (
    DEFAULT_THRESHOLDS,
    MITRE_ICS_ATTACKS,
    ModbusEvent,
    ModbusRuleViolation,
    RuleEngine,
    evaluate_modbus_event,
)

__all__ = [
    "DEFAULT_THRESHOLDS",
    "MITRE_ICS_ATTACKS",
    "ModbusEvent",
    "ModbusRuleViolation",
    "RuleEngine",
    "evaluate_modbus_event",
]
