import logging
import json
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable
from collections import defaultdict
from threading import Lock
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from models.alert import Alert, AlertLevel, AlertStatus

logger = logging.getLogger(__name__)

class AlertService:
    """Manages alerts: storage, retrieval, and notifications"""
    
    def __init__(self, log_file: str = 'ids_alerts.log', max_alerts: int = 10000):
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: List[str] = []  # Ordered list of alert IDs
        self.max_alerts = max_alerts
        self.log_file = log_file
        self._lock = Lock()
        
        # Statistics
        self.stats = {
            'total_alerts': 0,
            'alerts_by_level': defaultdict(int),
            'alerts_by_type': defaultdict(int),
            'alerts_by_source': defaultdict(int)
        }
        
        # Notification callbacks
        self._notification_handlers: List[Callable[[Alert], None]] = []
        
        # Rate limiting to prevent alert fatigue
        self._rate_limit_cache: Dict[str, datetime] = {}
        self._rate_limit_seconds = 60  # Minimum seconds between duplicate alerts
        
        # Setup file logging
        self._setup_file_logger()
    
    def _setup_file_logger(self) -> None:
        """Configure file-based alert logging"""
        self.file_handler = logging.FileHandler(self.log_file)
        self.file_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.file_handler.setFormatter(formatter)
        
        self.alert_logger = logging.getLogger('ids.alerts')
        self.alert_logger.addHandler(self.file_handler)
        self.alert_logger.setLevel(logging.WARNING)
    
    def _generate_rate_limit_key(self, alert: Alert) -> str:
        """Generate a key for rate limiting similar alerts"""
        return f"{alert.alert_type}:{alert.source_ip}:{alert.destination_port}"
    
    def _is_rate_limited(self, alert: Alert) -> bool:
        """Check if this alert type should be rate limited"""
        key = self._generate_rate_limit_key(alert)
        now = datetime.utcnow()
        
        if key in self._rate_limit_cache:
            last_alert_time = self._rate_limit_cache[key]
            elapsed = (now - last_alert_time).total_seconds()
            if elapsed < self._rate_limit_seconds:
                return True
        
        self._rate_limit_cache[key] = now
        return False
    
    def _cleanup_old_alerts(self) -> None:
        """Remove oldest alerts when limit is exceeded"""
        while len(self.alert_history) > self.max_alerts:
            oldest_id = self.alert_history.pop(0)
            if oldest_id in self.alerts:
                del self.alerts[oldest_id]
    
    def _update_stats(self, alert: Alert) -> None:
        """Update alert statistics"""
        self.stats['total_alerts'] += 1
        self.stats['alerts_by_level'][alert.level.name] += 1
        self.stats['alerts_by_type'][alert.alert_type] += 1
        self.stats['alerts_by_source'][alert.source_ip] += 1
    
    def _log_to_file(self, alert: Alert) -> None:
        """Write alert to log file"""
        log_level = {
            AlertLevel.LOW: logging.INFO,
            AlertLevel.MEDIUM: logging.WARNING,
            AlertLevel.HIGH: logging.ERROR,
            AlertLevel.CRITICAL: logging.CRITICAL
        }.get(alert.level, logging.WARNING)
        
        log_message = (
            f"[{alert.level.name}] {alert.alert_type} | "
            f"Source: {alert.source_ip} | "
            f"Dest: {alert.destination_ip}:{alert.destination_port} | "
            f"{alert.description}"
        )
        
        self.alert_logger.log(log_level, log_message)
    
    def _notify_handlers(self, alert: Alert) -> None:
        """Call all registered notification handlers"""
        for handler in self._notification_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Notification handler failed: {e}")
    
    def register_notification_handler(self, handler: Callable[[Alert], None]) -> None:
        """Register a callback for alert notifications"""
        self._notification_handlers.append(handler)
    
    def add_alert(self, alert: Alert, bypass_rate_limit: bool = False) -> Optional[str]:
        """
        Add a new alert to the system.
        Returns alert ID if added, None if rate limited.
        """
        # Check rate limiting
        if not bypass_rate_limit and self._is_rate_limited(alert):
            logger.debug(f"Alert rate limited: {alert.alert_type} from {alert.source_ip}")
            return None
        
        with self._lock:
            # Store alert
            self.alerts[alert.id] = alert
            self.alert_history.append(alert.id)
            
            # Update statistics
            self._update_stats(alert)
            
            # Cleanup if needed
            self._cleanup_old_alerts()
        
        # Log to file
        self._log_to_file(alert)
        
        # Notify handlers
        self._notify_handlers(alert)
        
        logger.info(f"Alert created: {alert.id} - {alert.alert_type}")
        return alert.id
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve a specific alert by ID"""
        return self.alerts.get(alert_id)
    
    def get_alerts(
        self,
        level: Optional[AlertLevel] = None,
        status: Optional[AlertStatus] = None,
        source_ip: Optional[str] = None,
        alert_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        """
        Retrieve alerts with optional filtering.
        Returns alerts in reverse chronological order (newest first).
        """
        filtered_alerts = []
        
        # Iterate in reverse for newest first
        for alert_id in reversed(self.alert_history):
            alert = self.alerts.get(alert_id)
            if not alert:
                continue
            
            # Apply filters
            if level and alert.level != level:
                continue
            if status and alert.status != status:
                continue
            if source_ip and alert.source_ip != source_ip:
                continue
            if alert_type and alert_type not in alert.alert_type:
                continue
            if since and alert.timestamp < since:
                continue
            
            filtered_alerts.append(alert)
        
        # Apply pagination
        return filtered_alerts[offset:offset + limit]
    
    def update_alert_status(
        self,
        alert_id: str,
        new_status: AlertStatus,
        notes: Optional[str] = None
    ) -> bool:
        """Update the status of an alert"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        
        with self._lock:
            alert.status = new_status
            if notes:
                alert.metadata['status_notes'] = notes
                alert.metadata['status_updated_at'] = datetime.utcnow().isoformat()
        
        logger.info(f"Alert {alert_id} status updated to {new_status.value}")
        return True
    
    def bulk_update_status(
        self,
        alert_ids: List[str],
        new_status: AlertStatus
    ) -> Dict[str, bool]:
        """Update status for multiple alerts"""
        results = {}
        for alert_id in alert_ids:
            results[alert_id] = self.update_alert_status(alert_id, new_status)
        return results
    
    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert"""
        if alert_id not in self.alerts:
            return False
        
        with self._lock:
            del self.alerts[alert_id]
            if alert_id in self.alert_history:
                self.alert_history.remove(alert_id)
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        # Calculate additional stats
        status_counts = defaultdict(int)
        recent_alerts = 0
        one_hour_ago = datetime.utcnow().replace(microsecond=0)
        
        for alert in self.alerts.values():
            status_counts[alert.status.value] += 1
            if (datetime.utcnow() - alert.timestamp).total_seconds() < 3600:
                recent_alerts += 1
        
        return {
            'total_alerts': self.stats['total_alerts'],
            'stored_alerts': len(self.alerts),
            'alerts_last_hour': recent_alerts,
            'by_level': dict(self.stats['alerts_by_level']),
            'by_status': dict(status_counts),
            'by_type': dict(sorted(
                self.stats['alerts_by_type'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_sources': dict(sorted(
                self.stats['alerts_by_source'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }
    
    def export_alerts(
        self,
        format: str = 'json',
        since: Optional[datetime] = None
    ) -> str:
        """Export alerts to specified format"""
        alerts = self.get_alerts(since=since, limit=self.max_alerts)
        
        if format == 'json':
            return json.dumps(
                [alert.to_dict() for alert in alerts],
                indent=2,
                default=str
            )
        elif format == 'csv':
            lines = ['id,timestamp,level,type,source_ip,destination_ip,destination_port,description,status']
            for alert in alerts:
                lines.append(
                    f'"{alert.id}","{alert.timestamp.isoformat()}","{alert.level.name}",'
                    f'"{alert.alert_type}","{alert.source_ip}","{alert.destination_ip or ""}",'
                    f'"{alert.destination_port or ""}","{alert.description}","{alert.status.value}"'
                )
            return '\n'.join(lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")


class EmailNotifier:
    """Email notification handler for alerts"""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_address: str,
        to_addresses: List[str],
        min_level: AlertLevel = AlertLevel.HIGH
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.min_level = min_level
    
    def __call__(self, alert: Alert) -> None:
        """Send email notification for alert"""
        if alert.level.value < self.min_level.value:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            msg['Subject'] = f"[IDS Alert - {alert.level.name}] {alert.alert_type}"
            
            body = f"""
Intrusion Detection System Alert

Level: {alert.level.name}
Type: {alert.alert_type}
Time: {alert.timestamp.isoformat()}

Source IP: {alert.source_ip}
Destination: {alert.destination_ip}:{alert.destination_port}

Description:
{alert.description}

Alert ID: {alert.id}

---
This is an automated message from the IDS.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent for alert {alert.id}")
        
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")


class WebhookNotifier:
    """Webhook notification handler for alerts"""
    
    def __init__(
        self,
        webhook_url: str,
        min_level: AlertLevel = AlertLevel.MEDIUM,
        headers: Optional[Dict[str, str]] = None
    ):
        self.webhook_url = webhook_url
        self.min_level = min_level
        self.headers = headers or {'Content-Type': 'application/json'}
    
    def __call__(self, alert: Alert) -> None:
        """Send webhook notification for alert"""
        if alert.level.value < self.min_level.value:
            return
        
        try:
            import requests
            
            payload = {
                'event': 'ids_alert',
                'alert': alert.to_dict()
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info(f"Webhook notification sent for alert {alert.id}")
        
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")