from typing import Protocol, List
from otwatch.events import OTEvent

class ProtocolParser(Protocol):
    name: str
    ports: tuple[int, ...]

    def matches(self, payload: bytes) -> bool: ...

    def parse(self, src: str, dst: str, sport: int, dport: int, payload: bytes, timestamp: float) -> List[OTEvent]: ...
