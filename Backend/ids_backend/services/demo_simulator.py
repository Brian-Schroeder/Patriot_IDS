"""
Demo simulator: generates simulated IDS alerts and packet data for attack types.
Works without live traffic capture - ideal for demos.
"""
import random
from datetime import datetime
from typing import List, Optional

from models.alert import Alert, AlertLevel
from services.alert_service import AlertService
from services.traffic_monitor import TrafficMonitor


# Simulated attacker IPs per attack type (consistent for demo clarity)
ATTACKER_IPS = {
    "Port Scan": "203.0.113.42",
    "DDoS": "198.51.100.15",
    "Brute Force": "192.0.2.77",
    "SQL Injection": "10.99.88.12",
    "XSS": "172.16.55.33",
    "Buffer Overflow": "192.168.100.200",
    "DNS Tunneling": "10.0.0.99",
    "Malware C2": "45.33.22.11",
}

# Default target (defender)
DEFAULT_TARGET = "10.0.1.50"


def simulate_attack(
    attack_type: str,
    alert_service: AlertService,
    traffic_monitor: Optional[TrafficMonitor],
    target_ip: Optional[str] = None,
) -> dict:
    """
    Simulate IDS response to an attack type.
    Creates alerts, optionally adds to recent packets, notifies SNS for HIGH/CRITICAL.
    """
    target = target_ip or DEFAULT_TARGET
    attacker_ip = ATTACKER_IPS.get(attack_type, "192.168.1.100")

    alerts_created: List[Alert] = []

    if attack_type == "Port Scan":
        alert = Alert(
            alert_type="ANOMALY:PORT_SCAN",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=22,
            description=f"Port scan detected from {attacker_ip}: 25 unique ports accessed (22, 23, 80, 443, 3306, ...)",
            level=AlertLevel.MEDIUM,
            metadata={"ports_scanned": 25, "attack_type": "Port Scan"},
        )
        alerts_created.append(alert)

    elif attack_type == "DDoS":
        alert = Alert(
            alert_type="ANOMALY:CONNECTION_FLOOD",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=80,
            description=f"DDoS/Connection flood: 500+ connections from {attacker_ip} in 60s",
            level=AlertLevel.CRITICAL,
            metadata={"connection_count": 500, "attack_type": "DDoS"},
        )
        alerts_created.append(alert)

    elif attack_type == "Brute Force":
        alert = Alert(
            alert_type="ANOMALY:BRUTE_FORCE",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=22,
            description=f"Brute force SSH attempt: 8 failed authentications from {attacker_ip}",
            level=AlertLevel.HIGH,
            metadata={"failed_attempts": 8, "attack_type": "Brute Force"},
        )
        alerts_created.append(alert)

    elif attack_type == "SQL Injection":
        alert = Alert(
            alert_type="SIGNATURE:SQL Injection Attempt",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=80,
            description="Detects common SQL injection patterns. Pattern matched: union select",
            level=AlertLevel.HIGH,
            metadata={"attack_type": "SQL Injection"},
        )
        alerts_created.append(alert)

    elif attack_type == "XSS":
        alert = Alert(
            alert_type="SIGNATURE:XSS Attempt",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=443,
            description="Detects cross-site scripting attempts. Pattern matched: <script>",
            level=AlertLevel.MEDIUM,
            metadata={"attack_type": "XSS"},
        )
        alerts_created.append(alert)

    elif attack_type == "Buffer Overflow":
        alert = Alert(
            alert_type="MALICIOUS_PAYLOAD",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=4444,
            description="Malicious pattern detected in payload: NOP sled",
            level=AlertLevel.HIGH,
            metadata={"attack_type": "Buffer Overflow"},
        )
        alerts_created.append(alert)

    elif attack_type == "DNS Tunneling":
        alert = Alert(
            alert_type="ANOMALY:DNS_TUNNELING",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=53,
            description=f"Unusual DNS query volume and payload patterns from {attacker_ip} - possible data exfiltration",
            level=AlertLevel.MEDIUM,
            metadata={"attack_type": "DNS Tunneling"},
        )
        alerts_created.append(alert)

    elif attack_type == "Malware C2":
        alert = Alert(
            alert_type="MALICIOUS_PAYLOAD",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=443,
            description="Malicious pattern detected in payload: cmd.exe",
            level=AlertLevel.CRITICAL,
            metadata={"attack_type": "Malware C2"},
        )
        alerts_created.append(alert)

    else:
        # Generic fallback
        alert = Alert(
            alert_type=f"DEMO:{attack_type}",
            source_ip=attacker_ip,
            destination_ip=target,
            description=f"Simulated detection of {attack_type} attack",
            level=AlertLevel.MEDIUM,
            metadata={"attack_type": attack_type},
        )
        alerts_created.append(alert)

    # Add alerts to alert service (bypass rate limit for demo)
    for alert in alerts_created:
        alert_service.add_alert(alert, bypass_rate_limit=True)

    # Notify SNS for HIGH/CRITICAL (don't let notification failures break the response)
    high_alerts = [a for a in alerts_created if a.level in (AlertLevel.HIGH, AlertLevel.CRITICAL)]
    if high_alerts:
        try:
            from services.alert_notification_service import notify_alerts
            notify_alerts(high_alerts)
        except Exception:
            pass  # SNS/notification failures should not break demo

    # Add to recent packets for Testing page "Packets Received" table
    if traffic_monitor:
        for alert in alerts_created:
            entry = {
                "timestamp": datetime.utcnow(),
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip or target,
                "source_port": 45000,
                "destination_port": alert.destination_port or 80,
                "protocol": "tcp",
                "size": 256,
                "alert_types": [alert.alert_type],
            }
            traffic_monitor._recent_packets.append(entry)

    return {
        "success": True,
        "attack_type": attack_type,
        "alerts_created": len(alerts_created),
        "alert_ids": [a.id for a in alerts_created],
        "target_ip": target,
        "attacker_ip": attacker_ip,
    }


def random_ip() -> str:
    """Generate a random IP for simulated traffic."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def live_tick(
    alert_service: AlertService,
    traffic_monitor: Optional[TrafficMonitor],
) -> dict:
    """
    Generate one batch of simulated live traffic. Mix of normal packets + occasional alert.
    Called periodically (e.g. every 2s) to simulate a live data stream.
    """
    target = DEFAULT_TARGET
    alerts_created = 0
    packets_added = 0

    # 1-4 normal-looking packets (no alert)
    n_normal = random.randint(1, 4)
    for _ in range(n_normal):
        packets_added += 1
        if traffic_monitor:
            traffic_monitor._recent_packets.append({
                "timestamp": datetime.utcnow(),
                "source_ip": random_ip(),
                "destination_ip": target,
                "source_port": random.randint(40000, 60000),
                "destination_port": random.choice([80, 443, 22, 8080]),
                "protocol": random.choice(["tcp", "udp"]),
                "size": random.randint(64, 1500),
                "alert_types": [],
            })

    # ~20% chance to generate an alert in this tick
    if random.random() < 0.2:
        attack_type = random.choice(list(ATTACKER_IPS.keys()))
        attacker_ip = ATTACKER_IPS[attack_type]
        alert = Alert(
            alert_type=f"LIVE:{attack_type}",
            source_ip=attacker_ip,
            destination_ip=target,
            destination_port=80,
            description=f"Simulated live stream: {attack_type} from {attacker_ip}",
            level=random.choice([AlertLevel.LOW, AlertLevel.MEDIUM, AlertLevel.HIGH]),
            metadata={"attack_type": attack_type, "live_stream": True},
        )
        alert_service.add_alert(alert, bypass_rate_limit=True)
        alerts_created += 1
        packets_added += 1
        if traffic_monitor:
            traffic_monitor._recent_packets.append({
                "timestamp": datetime.utcnow(),
                "source_ip": attacker_ip,
                "destination_ip": target,
                "source_port": random.randint(40000, 60000),
                "destination_port": 80,
                "protocol": "tcp",
                "size": random.randint(200, 800),
                "alert_types": [alert.alert_type],
            })

    return {
        "success": True,
        "packets": packets_added,
        "alerts": alerts_created,
    }
