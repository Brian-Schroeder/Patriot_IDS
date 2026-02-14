from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
import uuid

class AlertLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AlertStatus(Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

@dataclass
class Alert:
    alert_type: str
    source_ip: str
    description: str
    level: AlertLevel
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    status: AlertStatus = AlertStatus.NEW
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'description': self.description,
            'level': self.level.name,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }