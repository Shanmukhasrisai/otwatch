from dataclasses import dataclass
from typing import Optional, Union

@dataclass
class OTEvent:
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    protocol: str
    asset_id: Optional[str]
    zone: Optional[str]
    direction: str  # "request" | "response"
    operation: str  # "read" | "write"
    function: int
    object: Optional[str]
    value: Optional[Union[str, int]]
    session: Optional[str]
    confidence: float
    severity: Optional[str]
    detection_id: Optional[str]
