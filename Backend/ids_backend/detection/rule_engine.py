from typing import List, Optional, Dict, Any
from models.rule import DetectionRule, RuleAction
from models.alert import Alert, AlertLevel
from detection.packet_analyzer import PacketInfo
import logging

logger = logging.getLogger(__name__)

class RuleEngine:
    """Signature-based detection using configurable rules"""
    
    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load built-in detection rules"""
        default_rules = [
            DetectionRule(
                name="SQL Injection Attempt",
                pattern=r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table)",
                action=RuleAction.ALERT,
                alert_level="HIGH",
                description="Detects common SQL injection patterns",
                tags=["sqli", "web", "injection"]
            ),
            DetectionRule(
                name="XSS Attempt",
                pattern=r"(<script|javascript:|on\w+\s*=)",
                action=RuleAction.ALERT,
                alert_level="MEDIUM",
                description="Detects cross-site scripting attempts",
                tags=["xss", "web", "injection"]
            ),
            DetectionRule(
                name="Path Traversal",
                pattern=r"(\.\.\/|\.\.\\|%2e%2e%2f)",
                action=RuleAction.ALERT,
                alert_level="HIGH",
                description="Detects directory traversal attempts",
                tags=["lfi", "traversal", "web"]
            ),
            DetectionRule(
                name="Shell Command Injection",
                pattern=r"(;\s*cat\s|;\s*ls\s|`.*`|\$\(.*\)|&&\s*whoami)",
                action=RuleAction.ALERT,
                alert_level="CRITICAL",
                description="Detects shell command injection",
                tags=["rce", "injection", "shell"]
            ),
            DetectionRule(
                name="Sensitive File Access",
                pattern=r"(/etc/passwd|/etc/shadow|\.htpasswd|web\.config)",
                action=RuleAction.ALERT,
                alert_level="HIGH",
                description="Detects attempts to access sensitive files",
                tags=["lfi", "sensitive", "recon"]
            ),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: DetectionRule) -> str:
        """Add a detection rule"""
        self.rules[rule.id] = rule
        logger.info(f"Added rule: {rule.name} (ID: {rule.id})")
        return rule.id
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a rule by ID"""
        return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[DetectionRule]:
        """Get all rules"""
        return list(self.rules.values())
    
    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled
            return True
        return False
    
    def evaluate(self, packet: PacketInfo) -> List[Alert]:
        """Evaluate packet against all enabled rules"""
        alerts = []
        payload_str = packet.payload.decode('utf-8', errors='replace')
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            # Check protocol match
            if rule.protocol and rule.protocol != 'any':
                if rule.protocol.lower() != packet.protocol.lower():
                    continue
            
            # Check port match
            if rule.destination_port and rule.destination_port != packet.destination_port:
                continue
            
            # Check pattern match
            if rule.matches_payload(payload_str):
                alert = Alert(
                    alert_type=f"SIGNATURE:{rule.name}",
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    destination_port=packet.destination_port,
                    description=f"{rule.description}. Pattern matched: {rule.pattern}",
                    level=AlertLevel[rule.alert_level],
                    metadata={
                        'rule_id': rule.id,
                        'rule_name': rule.name,
                        'tags': rule.tags,
                        'action': rule.action.value
                    }
                )
                alerts.append(alert)
                logger.warning(f"Rule triggered: {rule.name} from {packet.source_ip}")
        
        return alerts