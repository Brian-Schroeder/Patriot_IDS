from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import re
import uuid

class RuleAction(Enum):
    ALERT = "alert"
    LOG = "log"
    BLOCK = "block"

@dataclass
class DetectionRule:
    name: str
    pattern: str
    action: RuleAction
    alert_level: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    enabled: bool = True
    protocol: Optional[str] = None  # tcp, udp, icmp, any
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    
    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        if self.pattern:
            try:
                self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
            except re.error:
                self._compiled_pattern = None
    
    def matches_payload(self, payload: str) -> bool:
        if self._compiled_pattern:
            return bool(self._compiled_pattern.search(payload))
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'pattern': self.pattern,
            'action': self.action.value,
            'alert_level': self.alert_level,
            'enabled': self.enabled,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'tags': self.tags
        }