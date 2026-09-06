# Registry for protocol parsers
from typing import Callable, Dict, List, Type
from otwatch.protocols.base import ProtocolParser

_PARSERS: List[ProtocolParser] = []


def register_parser(cls: Type[ProtocolParser]):
    """Decorator to register a ProtocolParser class (or instance).
    Usage:
      @register_parser
      class ModbusParser: ...
    """
    # allow both classes and instances
    instance = cls() if callable(cls) and not hasattr(cls, "parse") else cls
    _PARSERS.append(instance)
    return cls


def get_parser_for_port(port: int):
    """Return the first parser matching the given TCP port, or None."""
    for p in _PARSERS:
        if getattr(p, "ports", ()) and port in p.ports:
            return p
    return None
