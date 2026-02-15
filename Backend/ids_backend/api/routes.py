from flask import Blueprint, request, jsonify, Response
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from functools import wraps
import logging

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from models.alert import AlertLevel, AlertStatus, Alert
from models.rule import DetectionRule, RuleAction
from services.alert_service import AlertService
from services.traffic_monitor import TrafficMonitor
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import AnomalyDetector

logger = logging.getLogger(__name__)

# Create blueprint
api = Blueprint('api', __name__, url_prefix='/api/v1')

# Service instances (will be initialized in app.py)
alert_service: Optional[AlertService] = None
traffic_monitor: Optional[TrafficMonitor] = None


def init_routes(
    _alert_service: AlertService,
    _traffic_monitor: TrafficMonitor
) -> None:
    """Initialize route dependencies"""
    global alert_service, traffic_monitor
    alert_service = _alert_service
    traffic_monitor = _traffic_monitor


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        # In production, validate against stored API keys
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        # Add proper API key validation here
        return f(*args, **kwargs)
    return decorated


def handle_errors(f):
    """Decorator for consistent error handling"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except KeyError as e:
            return jsonify({'error': f'Missing required field: {e}'}), 400
        except Exception as e:
            logger.error(f"API error: {e}", exc_info=True)
            return jsonify({'error': 'Internal server error'}), 500
    return decorated


# =============================================================================
# Health & Status Endpoints
# =============================================================================

@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


@api.route('/status', methods=['GET'])
@handle_errors
def get_status():
    """Get overall system status"""
    monitor_status = traffic_monitor.get_status() if traffic_monitor else {}
    alert_stats = alert_service.get_statistics() if alert_service else {}
    
    return jsonify({
        'system': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'monitor': monitor_status,
        'alerts': alert_stats
    })


@api.route('/stats', methods=['GET'])
@handle_errors
def get_statistics():
    """Get detailed system statistics"""
    return jsonify({
        'monitor': traffic_monitor.get_status() if traffic_monitor else {},
        'detection': traffic_monitor.get_detection_stats() if traffic_monitor else {},
        'alerts': alert_service.get_statistics() if alert_service else {}
    })


# =============================================================================
# Monitor Control Endpoints
# =============================================================================

@api.route('/monitor/start', methods=['POST'])
@handle_errors
def start_monitor():
    """Start the traffic monitor"""
    if not traffic_monitor:
        return jsonify({'error': 'Traffic monitor not initialized'}), 500
    
    data = request.get_json() or {}
    use_scapy = data.get('use_scapy', True)
    
    traffic_monitor.start(use_scapy=use_scapy)
    
    return jsonify({
        'message': 'Traffic monitor started',
        'status': traffic_monitor.get_status()
    })


@api.route('/monitor/stop', methods=['POST'])
@handle_errors
def stop_monitor():
    """Stop the traffic monitor"""
    if not traffic_monitor:
        return jsonify({'error': 'Traffic monitor not initialized'}), 500
    
    traffic_monitor.stop()
    
    return jsonify({
        'message': 'Traffic monitor stopped',
        'status': traffic_monitor.get_status()
    })


@api.route('/monitor/status', methods=['GET'])
@handle_errors
def get_monitor_status():
    """Get traffic monitor status"""
    if not traffic_monitor:
        return jsonify({'error': 'Traffic monitor not initialized'}), 500
    
    return jsonify(traffic_monitor.get_status())


@api.route('/monitor/inject', methods=['POST'])
@handle_errors
def inject_packet():
    """
    Inject a packet for analysis (testing/simulation).
    Useful for testing detection rules without live traffic.
    """
    if not traffic_monitor:
        return jsonify({'error': 'Traffic monitor not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Packet data required'}), 400
    
    # Validate required fields
    required_fields = ['src_ip', 'dst_ip']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Set defaults for optional fields
    packet_data = {
        'src_ip': data['src_ip'],
        'dst_ip': data['dst_ip'],
        'src_port': data.get('src_port', 0),
        'dst_port': data.get('dst_port', 0),
        'protocol': data.get('protocol', 'tcp'),
        'payload': data.get('payload', '').encode() if isinstance(data.get('payload'), str) else data.get('payload', b''),
        'size': data.get('size', 100),
        'flags': data.get('flags', {})
    }
    
    traffic_monitor.inject_packet(packet_data)
    
    return jsonify({
        'message': 'Packet injected for analysis',
        'packet': {
            'src_ip': packet_data['src_ip'],
            'dst_ip': packet_data['dst_ip'],
            'protocol': packet_data['protocol']
        }
    })


# =============================================================================
# VPC Flow Logs Ingestion (AWS)
# =============================================================================

_PROTOCOL_MAP = {6: 'tcp', 17: 'udp', 1: 'icmp'}


def _flow_log_to_packet(record: dict) -> dict:
    """Convert VPC Flow Log record to packet_data format for TrafficMonitor."""
    protocol_num = record.get('protocol', 6)
    protocol = _PROTOCOL_MAP.get(int(protocol_num) if protocol_num != '-' else 6, 'tcp')
    src_port = int(record.get('srcport', 0)) if record.get('srcport', '-') != '-' else 0
    dst_port = int(record.get('dstport', 0)) if record.get('dstport', '-') != '-' else 0
    packets = int(record.get('packets', 1)) if record.get('packets', '-') != '-' else 1
    bytes_val = int(record.get('bytes', 100)) if record.get('bytes', '-') != '-' else 100

    return {
        'src_ip': record.get('srcaddr', '0.0.0.0'),
        'dst_ip': record.get('dstaddr', '0.0.0.0'),
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'payload': b'',
        'size': bytes_val,
        'flags': {},
        '_flow_packets': packets,
    }


@api.route('/attack/start', methods=['POST'])
@handle_errors
def start_attack():
    """
    Signal the attacker VM to start an attack.
    Proxies the command to the attacker.

    Request body:
    - attackType: One of Port Scan, DDoS, Brute Force, SQL Injection, XSS, etc.
    - attackerUrl: URL of attacker (e.g. http://10.0.1.100:9999)
    - targetIp: (optional) Override target IP for the attacker. Defaults to this host.
    """
    if not HAS_REQUESTS:
        return jsonify({'error': 'requests library required for attacker proxy', 'success': False}), 500

    data = request.get_json()
    if not data or 'attackType' not in data:
        return jsonify({'error': 'attackType required', 'success': False}), 400

    attack_type = data['attackType']
    attacker_url = data.get('attackerUrl', '').strip()
    target_ip = data.get('targetIp', '').strip()

    if not attacker_url:
        return jsonify({
            'error': 'attackerUrl required. Configure the attacker IP in the Testing section.',
            'success': False,
        }), 400

    # Ensure URL has scheme
    if not attacker_url.startswith(('http://', 'https://')):
        attacker_url = f"http://{attacker_url}"

    # Build forward payload
    payload = {'attackType': attack_type}
    if target_ip:
        payload['targetIp'] = target_ip

    try:
        r = req_lib.post(
            f"{attacker_url.rstrip('/')}/attack/start",
            json=payload,
            timeout=10,
            headers={'Content-Type': 'application/json'},
        )
        r.raise_for_status()
        result = r.json()
        return jsonify({'success': True, **result})
    except req_lib.RequestException as e:
        logger.warning(f"Attacker proxy failed: {e}")
        return jsonify({
            'success': False,
            'message': f"Cannot reach attacker: {str(e)}. Ensure attacker VM is running and reachable.",
        }), 502


@api.route('/packets', methods=['GET'])
@handle_errors
def get_packets():
    """Get recently processed packets (from traffic capture/inject)."""
    if not traffic_monitor:
        return jsonify([])
    return jsonify(traffic_monitor.get_recent_packets())


@api.route('/flow-logs/inject', methods=['POST'])
@handle_errors
def inject_flow_logs():
    """
    Inject VPC Flow Log records for analysis.
    Accepts AWS VPC Flow Log format (parsed) as JSON.

    Request body:
    - records: List of flow log records. Each record can be:
      - Object with fields: srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes
      - Or raw string (space-separated) which will be parsed

    Used by Lambda/ingestion pipeline that reads from CloudWatch Logs or S3.
    """
    if not traffic_monitor:
        return jsonify({'error': 'Traffic monitor not initialized'}), 500

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    records = data.get('records', data) if isinstance(data, dict) else []
    if not isinstance(records, list):
        records = [records]

    injected = 0
    for rec in records:
        try:
            if isinstance(rec, str):
                parts = rec.split()
                if len(parts) >= 12:
                    rec = {
                        'srcaddr': parts[3],
                        'dstaddr': parts[4],
                        'srcport': parts[5],
                        'dstport': parts[6],
                        'protocol': parts[7],
                        'packets': parts[8],
                        'bytes': parts[9],
                    }
                else:
                    continue
            packet_data = _flow_log_to_packet(rec)
            for _ in range(packet_data.pop('_flow_packets', 1)):
                traffic_monitor.inject_packet(packet_data)
                injected += 1
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Skipping invalid flow log record: {e}")
            continue

    return jsonify({
        'message': 'Flow logs ingested',
        'injected': injected,
        'records_processed': len(records),
    })


# =============================================================================
# Notification Endpoints (AWS SNS Topic)
# =============================================================================

from services.sns_notifier import send_test_notification


@api.route('/notifications/test', methods=['POST'])
@handle_errors
def test_notification():
    """
    Send a test alert to the SNS topic. Email subscribers are configured in AWS.
    Configure: SNS_TOPIC_ARN (default: arn:aws:sns:us-east-1:988718950747:nids-alerts)
    """
    ok, msg = send_test_notification()
    return jsonify({'success': ok, 'message': msg})


# =============================================================================
# Alert Endpoints
# =============================================================================

@api.route('/alerts', methods=['GET'])
@handle_errors
def get_alerts():
    """
    Get alerts with optional filtering.
    
    Query parameters:
    - level: Filter by alert level (LOW, MEDIUM, HIGH, CRITICAL)
    - status: Filter by status (new, acknowledged, resolved, false_positive)
    - source_ip: Filter by source IP
    - type: Filter by alert type (partial match)
    - since: Filter alerts after this ISO timestamp
    - limit: Maximum number of alerts to return (default: 100)
    - offset: Pagination offset (default: 0)
    """
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    # Parse query parameters
    level = request.args.get('level')
    status = request.args.get('status')
    source_ip = request.args.get('source_ip')
    alert_type = request.args.get('type')
    since_str = request.args.get('since')
    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))
    
    # Convert string parameters to enums
    level_enum = AlertLevel[level.upper()] if level else None
    status_enum = AlertStatus(status.lower()) if status else None
    since = datetime.fromisoformat(since_str) if since_str else None
    
    alerts = alert_service.get_alerts(
        level=level_enum,
        status=status_enum,
        source_ip=source_ip,
        alert_type=alert_type,
        since=since,
        limit=limit,
        offset=offset
    )
    
    return jsonify({
        'count': len(alerts),
        'limit': limit,
        'offset': offset,
        'alerts': [alert.to_dict() for alert in alerts]
    })


@api.route('/alerts/<alert_id>', methods=['GET'])
@handle_errors
def get_alert(alert_id: str):
    """Get a specific alert by ID"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    alert = alert_service.get_alert(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    return jsonify(alert.to_dict())


@api.route('/alerts/<alert_id>/status', methods=['PUT', 'PATCH'])
@handle_errors
def update_alert_status(alert_id: str):
    """Update alert status"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'error': 'Status field required'}), 400
    
    try:
        new_status = AlertStatus(data['status'].lower())
    except ValueError:
        valid_statuses = [s.value for s in AlertStatus]
        return jsonify({'error': f'Invalid status. Valid values: {valid_statuses}'}), 400
    
    notes = data.get('notes')
    
    success = alert_service.update_alert_status(alert_id, new_status, notes)
    if not success:
        return jsonify({'error': 'Alert not found'}), 404
    
    alert = alert_service.get_alert(alert_id)
    return jsonify({
        'message': 'Alert status updated',
        'alert': alert.to_dict()
    })


@api.route('/alerts/bulk/status', methods=['PUT', 'PATCH'])
@handle_errors
def bulk_update_alert_status():
    """Update status for multiple alerts"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    alert_ids = data.get('alert_ids', [])
    status = data.get('status')
    
    if not alert_ids:
        return jsonify({'error': 'alert_ids array required'}), 400
    if not status:
        return jsonify({'error': 'status field required'}), 400
    
    try:
        new_status = AlertStatus(status.lower())
    except ValueError:
        valid_statuses = [s.value for s in AlertStatus]
        return jsonify({'error': f'Invalid status. Valid values: {valid_statuses}'}), 400
    
    results = alert_service.bulk_update_status(alert_ids, new_status)
    
    return jsonify({
        'message': 'Bulk status update completed',
        'results': results,
        'updated': sum(1 for v in results.values() if v),
        'failed': sum(1 for v in results.values() if not v)
    })


@api.route('/alerts/<alert_id>', methods=['DELETE'])
@handle_errors
def delete_alert(alert_id: str):
    """Delete an alert"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    success = alert_service.delete_alert(alert_id)
    if not success:
        return jsonify({'error': 'Alert not found'}), 404
    
    return jsonify({'message': 'Alert deleted', 'alert_id': alert_id})


@api.route('/alerts/export', methods=['GET'])
@handle_errors
def export_alerts():
    """
    Export alerts in specified format.
    
    Query parameters:
    - format: Export format (json, csv). Default: json
    - since: Export alerts after this ISO timestamp
    """
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    export_format = request.args.get('format', 'json').lower()
    since_str = request.args.get('since')
    since = datetime.fromisoformat(since_str) if since_str else None
    
    if export_format not in ['json', 'csv']:
        return jsonify({'error': 'Invalid format. Supported: json, csv'}), 400
    
    content = alert_service.export_alerts(format=export_format, since=since)
    
    if export_format == 'json':
        return Response(
            content,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=alerts.json'}
        )
    else:
        return Response(
            content,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=alerts.csv'}
        )


@api.route('/alerts/statistics', methods=['GET'])
@handle_errors
def get_alert_statistics():
    """Get alert statistics"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    return jsonify(alert_service.get_statistics())


# =============================================================================
# Detection Rules Endpoints
# =============================================================================

@api.route('/rules', methods=['GET'])
@handle_errors
def get_rules():
    """Get all detection rules"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    rules = traffic_monitor.rule_engine.get_all_rules()
    
    return jsonify({
        'count': len(rules),
        'rules': [rule.to_dict() for rule in rules]
    })


@api.route('/rules/<rule_id>', methods=['GET'])
@handle_errors
def get_rule(rule_id: str):
    """Get a specific rule by ID"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    rule = traffic_monitor.rule_engine.get_rule(rule_id)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    return jsonify(rule.to_dict())


@api.route('/rules', methods=['POST'])
@handle_errors
def create_rule():
    """Create a new detection rule"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    # Validate required fields
    required = ['name', 'pattern', 'alert_level']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Validate alert level
    valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if data['alert_level'].upper() not in valid_levels:
        return jsonify({'error': f'Invalid alert_level. Valid values: {valid_levels}'}), 400
    
    # Validate action
    action_str = data.get('action', 'alert').lower()
    try:
        action = RuleAction(action_str)
    except ValueError:
        valid_actions = [a.value for a in RuleAction]
        return jsonify({'error': f'Invalid action. Valid values: {valid_actions}'}), 400
    
    # Create rule
    rule = DetectionRule(
        name=data['name'],
        pattern=data['pattern'],
        action=action,
        alert_level=data['alert_level'].upper(),
        description=data.get('description', ''),
        enabled=data.get('enabled', True),
        protocol=data.get('protocol'),
        source_ip=data.get('source_ip'),
        destination_ip=data.get('destination_ip'),
        source_port=data.get('source_port'),
        destination_port=data.get('destination_port'),
        tags=data.get('tags', [])
    )
    
    rule_id = traffic_monitor.rule_engine.add_rule(rule)
    
    return jsonify({
        'message': 'Rule created successfully',
        'rule': rule.to_dict()
    }), 201


@api.route('/rules/<rule_id>', methods=['PUT'])
@handle_errors
def update_rule(rule_id: str):
    """Update an existing detection rule"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    existing_rule = traffic_monitor.rule_engine.get_rule(rule_id)
    if not existing_rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    # Validate action if provided
    if 'action' in data:
        try:
            action = RuleAction(data['action'].lower())
        except ValueError:
            valid_actions = [a.value for a in RuleAction]
            return jsonify({'error': f'Invalid action. Valid values: {valid_actions}'}), 400
    else:
        action = existing_rule.action
    
    # Validate alert level if provided
    if 'alert_level' in data:
        valid_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if data['alert_level'].upper() not in valid_levels:
            return jsonify({'error': f'Invalid alert_level. Valid values: {valid_levels}'}), 400
        alert_level = data['alert_level'].upper()
    else:
        alert_level = existing_rule.alert_level
    
    # Create updated rule (preserving ID)
    updated_rule = DetectionRule(
        id=rule_id,
        name=data.get('name', existing_rule.name),
        pattern=data.get('pattern', existing_rule.pattern),
        action=action,
        alert_level=alert_level,
        description=data.get('description', existing_rule.description),
        enabled=data.get('enabled', existing_rule.enabled),
        protocol=data.get('protocol', existing_rule.protocol),
        source_ip=data.get('source_ip', existing_rule.source_ip),
        destination_ip=data.get('destination_ip', existing_rule.destination_ip),
        source_port=data.get('source_port', existing_rule.source_port),
        destination_port=data.get('destination_port', existing_rule.destination_port),
        tags=data.get('tags', existing_rule.tags)
    )
    
    # Remove old and add updated
    traffic_monitor.rule_engine.remove_rule(rule_id)
    traffic_monitor.rule_engine.rules[rule_id] = updated_rule
    
    return jsonify({
        'message': 'Rule updated successfully',
        'rule': updated_rule.to_dict()
    })


@api.route('/rules/<rule_id>', methods=['DELETE'])
@handle_errors
def delete_rule(rule_id: str):
    """Delete a detection rule"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    success = traffic_monitor.rule_engine.remove_rule(rule_id)
    if not success:
        return jsonify({'error': 'Rule not found'}), 404
    
    return jsonify({
        'message': 'Rule deleted successfully',
        'rule_id': rule_id
    })


@api.route('/rules/<rule_id>/toggle', methods=['POST'])
@handle_errors
def toggle_rule(rule_id: str):
    """Enable or disable a detection rule"""
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    data = request.get_json()
    if data is None or 'enabled' not in data:
        return jsonify({'error': 'enabled field required'}), 400
    
    enabled = bool(data['enabled'])
    success = traffic_monitor.rule_engine.toggle_rule(rule_id, enabled)
    
    if not success:
        return jsonify({'error': 'Rule not found'}), 404
    
    rule = traffic_monitor.rule_engine.get_rule(rule_id)
    return jsonify({
        'message': f"Rule {'enabled' if enabled else 'disabled'}",
        'rule': rule.to_dict()
    })


@api.route('/rules/test', methods=['POST'])
@handle_errors
def test_rule():
    """
    Test a rule pattern against sample payload without creating the rule.
    Useful for validating rules before deployment.
    """
    if not traffic_monitor or not traffic_monitor.rule_engine:
        return jsonify({'error': 'Rule engine not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    pattern = data.get('pattern')
    payload = data.get('payload', '')
    
    if not pattern:
        return jsonify({'error': 'pattern field required'}), 400
    
    # Create temporary rule for testing
    import re
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
        match = compiled.search(payload)
        
        return jsonify({
            'pattern': pattern,
            'payload': payload,
            'matches': match is not None,
            'match_details': {
                'matched_text': match.group() if match else None,
                'start': match.start() if match else None,
                'end': match.end() if match else None
            } if match else None
        })
    except re.error as e:
        return jsonify({
            'error': f'Invalid regex pattern: {str(e)}',
            'pattern': pattern
        }), 400


# =============================================================================
# Anomaly Detection Configuration Endpoints
# =============================================================================

@api.route('/anomaly/thresholds', methods=['GET'])
@handle_errors
def get_anomaly_thresholds():
    """Get current anomaly detection thresholds"""
    if not traffic_monitor or not traffic_monitor.anomaly_detector:
        return jsonify({'error': 'Anomaly detector not initialized'}), 500
    
    return jsonify({
        'thresholds': traffic_monitor.anomaly_detector.thresholds,
        'time_window_seconds': traffic_monitor.anomaly_detector.time_window.total_seconds()
    })


@api.route('/anomaly/thresholds', methods=['PUT', 'PATCH'])
@handle_errors
def update_anomaly_thresholds():
    """Update anomaly detection thresholds"""
    if not traffic_monitor or not traffic_monitor.anomaly_detector:
        return jsonify({'error': 'Anomaly detector not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    # Validate threshold values
    valid_thresholds = [
        'packets_per_second',
        'bytes_per_second',
        'connections_per_ip',
        'port_scan_threshold',
        'failed_auth_threshold',
        'syn_flood_threshold',
        'std_deviation_multiplier'
    ]
    
    updates = {}
    for key, value in data.items():
        if key not in valid_thresholds:
            return jsonify({'error': f'Invalid threshold: {key}. Valid: {valid_thresholds}'}), 400
        if not isinstance(value, (int, float)) or value < 0:
            return jsonify({'error': f'Threshold {key} must be a positive number'}), 400
        updates[key] = value
    
    traffic_monitor.anomaly_detector.update_thresholds(updates)
    
    return jsonify({
        'message': 'Thresholds updated',
        'thresholds': traffic_monitor.anomaly_detector.thresholds
    })


@api.route('/anomaly/statistics', methods=['GET'])
@handle_errors
def get_anomaly_statistics():
    """Get anomaly detection statistics and baseline data"""
    if not traffic_monitor or not traffic_monitor.anomaly_detector:
        return jsonify({'error': 'Anomaly detector not initialized'}), 500
    
    return jsonify(traffic_monitor.anomaly_detector.get_statistics())


@api.route('/anomaly/baseline/reset', methods=['POST'])
@handle_errors
def reset_anomaly_baseline():
    """Reset the anomaly detection baseline"""
    if not traffic_monitor or not traffic_monitor.anomaly_detector:
        return jsonify({'error': 'Anomaly detector not initialized'}), 500
    
    # Reset baseline by creating new detector with same thresholds
    old_thresholds = traffic_monitor.anomaly_detector.thresholds.copy()
    traffic_monitor.anomaly_detector = AnomalyDetector()
    traffic_monitor.anomaly_detector.update_thresholds(old_thresholds)
    
    return jsonify({
        'message': 'Anomaly baseline reset successfully',
        'thresholds': traffic_monitor.anomaly_detector.thresholds
    })


@api.route('/anomaly/failed-auth', methods=['POST'])
@handle_errors
def record_failed_auth():
    """
    Record a failed authentication attempt.
    Call this from your authentication system to enable brute force detection.
    """
    if not traffic_monitor or not traffic_monitor.anomaly_detector:
        return jsonify({'error': 'Anomaly detector not initialized'}), 500
    
    data = request.get_json()
    if not data or 'source_ip' not in data:
        return jsonify({'error': 'source_ip field required'}), 400
    
    source_ip = data['source_ip']
    traffic_monitor.anomaly_detector.record_failed_auth(source_ip)
    
    # Check if this triggers an alert
    failed_count = len(traffic_monitor.anomaly_detector.failed_auth_tracker.get(source_ip, []))
    threshold = traffic_monitor.anomaly_detector.thresholds['failed_auth_threshold']
    
    return jsonify({
        'message': 'Failed authentication recorded',
        'source_ip': source_ip,
        'failed_attempts': failed_count,
        'threshold': threshold,
        'alert_triggered': failed_count > threshold
    })


# =============================================================================
# Blocklist Management Endpoints
# =============================================================================

# In-memory blocklist (in production, use persistent storage)
_blocklist: Dict[str, dict] = {}


@api.route('/blocklist', methods=['GET'])
@handle_errors
def get_blocklist():
    """Get all blocked IPs"""
    return jsonify({
        'count': len(_blocklist),
        'blocked_ips': list(_blocklist.values())
    })


@api.route('/blocklist', methods=['POST'])
@handle_errors
def add_to_blocklist():
    """Add an IP to the blocklist"""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'ip field required'}), 400
    
    ip = data['ip']
    reason = data.get('reason', 'Manual block')
    expires_in = data.get('expires_in_hours')  # Optional expiration
    
    entry = {
        'ip': ip,
        'reason': reason,
        'blocked_at': datetime.utcnow().isoformat(),
        'expires_at': (datetime.utcnow() + timedelta(hours=expires_in)).isoformat() if expires_in else None,
        'blocked_by': data.get('blocked_by', 'api')
    }
    
    _blocklist[ip] = entry
    logger.info(f"IP blocked: {ip} - Reason: {reason}")
    
    return jsonify({
        'message': 'IP added to blocklist',
        'entry': entry
    }), 201


@api.route('/blocklist/<ip>', methods=['DELETE'])
@handle_errors
def remove_from_blocklist(ip: str):
    """Remove an IP from the blocklist"""
    if ip not in _blocklist:
        return jsonify({'error': 'IP not found in blocklist'}), 404
    
    del _blocklist[ip]
    logger.info(f"IP unblocked: {ip}")
    
    return jsonify({
        'message': 'IP removed from blocklist',
        'ip': ip
    })


@api.route('/blocklist/check/<ip>', methods=['GET'])
@handle_errors
def check_blocklist(ip: str):
    """Check if an IP is blocked"""
    entry = _blocklist.get(ip)
    
    if entry:
        # Check expiration
        if entry.get('expires_at'):
            expires_at = datetime.fromisoformat(entry['expires_at'])
            if datetime.utcnow() > expires_at:
                del _blocklist[ip]
                return jsonify({'blocked': False, 'ip': ip})
        
        return jsonify({
            'blocked': True,
            'ip': ip,
            'entry': entry
        })
    
    return jsonify({'blocked': False, 'ip': ip})


# =============================================================================
# Dashboard / Summary Endpoints
# =============================================================================

@api.route('/dashboard/summary', methods=['GET'])
@handle_errors
def get_dashboard_summary():
    """Get summary data for dashboard display"""
    if not alert_service or not traffic_monitor:
        return jsonify({'error': 'Services not initialized'}), 500
    
    # Get time-based alert counts
    now = datetime.utcnow()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)
    
    alerts_last_hour = alert_service.get_alerts(since=last_hour, limit=10000)
    alerts_last_24h = alert_service.get_alerts(since=last_24h, limit=10000)
    
    # Count by severity for last 24h
    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in alerts_last_24h:
        severity_counts[alert.level.name] += 1
    
    # Count by status
    status_counts = {'new': 0, 'acknowledged': 0, 'resolved': 0, 'false_positive': 0}
    for alert in alerts_last_24h:
        status_counts[alert.status.value] += 1
    
    # Get top attacking IPs
    ip_counts = {}
    for alert in alerts_last_24h:
        ip_counts[alert.source_ip] = ip_counts.get(alert.source_ip, 0) + 1
    top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get top alert types
    type_counts = {}
    for alert in alerts_last_24h:
        type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
    top_alert_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get monitor status
    monitor_status = traffic_monitor.get_status()
    
    # Get recent critical alerts
    critical_alerts = [
        a.to_dict() for a in alerts_last_24h 
        if a.level == AlertLevel.CRITICAL and a.status == AlertStatus.NEW
    ][:5]
    
    return jsonify({
        'timestamp': now.isoformat(),
        'monitor': {
            'status': 'running' if monitor_status['is_running'] else 'stopped',
            'uptime_seconds': monitor_status.get('uptime_seconds', 0),
            'packets_per_second': monitor_status.get('packets_per_second', 0),
            'total_packets': monitor_status.get('packets_processed', 0)
        },
        'alerts': {
            'last_hour': len(alerts_last_hour),
            'last_24h': len(alerts_last_24h),
            'by_severity': severity_counts,
            'by_status': status_counts,
            'unacknowledged': status_counts['new']
        },
        'threats': {
            'top_attackers': [{'ip': ip, 'count': count} for ip, count in top_attackers],
            'top_alert_types': [{'type': t, 'count': count} for t, count in top_alert_types],
            'recent_critical': critical_alerts
        },
        'blocklist': {
            'total_blocked': len(_blocklist)
        }
    })


@api.route('/dashboard/timeline', methods=['GET'])
@handle_errors
def get_alert_timeline():
    """
    Get alert counts over time for timeline visualization.
    
    Query parameters:
    - hours: Number of hours to look back (default: 24, max: 168)
    - interval: Grouping interval in minutes (default: 60)
    """
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    hours = min(int(request.args.get('hours', 24)), 168)  # Max 1 week
    interval = max(int(request.args.get('interval', 60)), 5)  # Min 5 minutes
    
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    # Get all alerts in range
    alerts = alert_service.get_alerts(since=start_time, limit=50000)
    
    # Create time buckets
    buckets = {}
    current = start_time
    while current <= now:
        bucket_key = current.strftime('%Y-%m-%d %H:%M')
        buckets[bucket_key] = {
            'timestamp': current.isoformat(),
            'total': 0,
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
        current += timedelta(minutes=interval)
    
    # Populate buckets
    for alert in alerts:
        # Find the appropriate bucket
        alert_time = alert.timestamp
        bucket_time = alert_time.replace(
            minute=(alert_time.minute // interval) * interval,
            second=0,
            microsecond=0
        )
        bucket_key = bucket_time.strftime('%Y-%m-%d %H:%M')
        
        if bucket_key in buckets:
            buckets[bucket_key]['total'] += 1
            buckets[bucket_key][alert.level.name.lower()] += 1
    
    # Convert to list sorted by time
    timeline = sorted(buckets.values(), key=lambda x: x['timestamp'])
    
    return jsonify({
        'start_time': start_time.isoformat(),
        'end_time': now.isoformat(),
        'interval_minutes': interval,
        'data_points': len(timeline),
        'timeline': timeline
    })


@api.route('/dashboard/geo', methods=['GET'])
@handle_errors
def get_geo_summary():
    """
    Get geographic distribution of attack sources.
    Note: Requires GeoIP database integration for production use.
    This is a placeholder that returns IP-based groupings.
    """
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    hours = int(request.args.get('hours', 24))
    since = datetime.utcnow() - timedelta(hours=hours)
    
    alerts = alert_service.get_alerts(since=since, limit=10000)
    
    # Group by IP prefix (simplified geo approximation)
    # In production, use MaxMind GeoIP or similar
    ip_groups = {}
    for alert in alerts:
        ip = alert.source_ip
        if ip and ip != 'multiple':
            # Group by /16 subnet as rough approximation
            parts = ip.split('.')
            if len(parts) >= 2:
                prefix = f"{parts[0]}.{parts[1]}.0.0/16"
                if prefix not in ip_groups:
                    ip_groups[prefix] = {
                        'subnet': prefix,
                        'count': 0,
                        'unique_ips': set(),
                        'alert_types': set()
                    }
                ip_groups[prefix]['count'] += 1
                ip_groups[prefix]['unique_ips'].add(ip)
                ip_groups[prefix]['alert_types'].add(alert.alert_type)
    
    # Convert sets to lists for JSON serialization
    geo_data = []
    for prefix, data in ip_groups.items():
        geo_data.append({
            'subnet': prefix,
            'alert_count': data['count'],
            'unique_ips': len(data['unique_ips']),
            'alert_types': list(data['alert_types'])
        })
    
    # Sort by count
    geo_data.sort(key=lambda x: x['alert_count'], reverse=True)
    
    return jsonify({
        'time_range_hours': hours,
        'total_sources': len(geo_data),
        'sources': geo_data[:50]  # Top 50
    })


# =============================================================================
# Report Generation Endpoints
# =============================================================================

@api.route('/reports/daily', methods=['GET'])
@handle_errors
def get_daily_report():
    """Generate a daily security report"""
    if not alert_service or not traffic_monitor:
        return jsonify({'error': 'Services not initialized'}), 500
    
    # Get date parameter or default to today
    date_str = request.args.get('date')
    if date_str:
        report_date = datetime.fromisoformat(date_str).date()
    else:
        report_date = datetime.utcnow().date()
    
    start_time = datetime.combine(report_date, datetime.min.time())
    end_time = datetime.combine(report_date, datetime.max.time())
    
    # Get alerts for the day
    alerts = alert_service.get_alerts(since=start_time, limit=50000)
    day_alerts = [a for a in alerts if a.timestamp <= end_time]
    
    # Compile statistics
    severity_breakdown = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    type_breakdown = {}
    source_breakdown = {}
    hourly_distribution = {str(h).zfill(2): 0 for h in range(24)}
    
    for alert in day_alerts:
        severity_breakdown[alert.level.name] += 1
        type_breakdown[alert.alert_type] = type_breakdown.get(alert.alert_type, 0) + 1
        source_breakdown[alert.source_ip] = source_breakdown.get(alert.source_ip, 0) + 1
        hour = str(alert.timestamp.hour).zfill(2)
        hourly_distribution[hour] += 1
    
    # Get top items
    top_types = sorted(type_breakdown.items(), key=lambda x: x[1], reverse=True)[:10]
    top_sources = sorted(source_breakdown.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Find peak hour
    peak_hour = max(hourly_distribution.items(), key=lambda x: x[1])
    
    report = {
        'report_type': 'daily',
        'report_date': report_date.isoformat(),
        'generated_at': datetime.utcnow().isoformat(),
        'summary': {
            'total_alerts': len(day_alerts),
            'critical_alerts': severity_breakdown['CRITICAL'],
            'high_alerts': severity_breakdown['HIGH'],
            'unique_sources': len(source_breakdown),
            'unique_alert_types': len(type_breakdown)
        },
        'severity_breakdown': severity_breakdown,
        'top_alert_types': [{'type': t, 'count': c} for t, c in top_types],
        'top_sources': [{'ip': ip, 'count': c} for ip, c in top_sources],
        'hourly_distribution': hourly_distribution,
        'peak_activity': {
            'hour': f"{peak_hour[0]}:00",
            'alert_count': peak_hour[1]
        },
        'recommendations': _generate_recommendations(severity_breakdown, top_sources, top_types)
    }
    
    return jsonify(report)


def _generate_recommendations(severity: dict, top_sources: list, top_types: list) -> list:
    """Generate security recommendations based on alert data"""
    recommendations = []
    
    # High critical alert count
    if severity['CRITICAL'] > 10:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Incident Response',
            'recommendation': f"Investigate {severity['CRITICAL']} critical alerts immediately. Consider engaging incident response team."
        })
    
    # Repeated attacks from same source
    if top_sources and top_sources[0][1] > 50:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Blocking',
            'recommendation': f"Consider blocking IP {top_sources[0][0]} - responsible for {top_sources[0][1]} alerts."
        })
    
    # SQL injection prevalent
    sqli_count = sum(c for t, c in top_types if 'SQL' in t.upper())
    if sqli_count > 20:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Application Security',
            'recommendation': "High volume of SQL injection attempts detected. Review application input validation and WAF rules."
        })
    
    # Port scanning activity
    scan_count = sum(c for t, c in top_types if 'SCAN' in t.upper())
    if scan_count > 30:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Network Security',
            'recommendation': "Significant port scanning activity detected. Review firewall rules and consider rate limiting."
        })
    
    # Brute force attempts
    brute_count = sum(c for t, c in top_types if 'BRUTE' in t.upper() or 'AUTH' in t.upper())
    if brute_count > 20:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Authentication',
            'recommendation': "Multiple brute force attempts detected. Ensure account lockout policies are in place and consider implementing MFA."
        })
    
    if not recommendations:
        recommendations.append({
            'priority': 'LOW',
            'category': 'General',
            'recommendation': "No critical issues detected. Continue monitoring and maintain current security posture."
        })
    
    return recommendations


@api.route('/reports/weekly', methods=['GET'])
@handle_errors
def get_weekly_report():
    """Generate a weekly security report"""
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    # Get week parameter or default to current week
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    
    alerts = alert_service.get_alerts(since=start_date, limit=100000)
    
    # Daily breakdown
    daily_counts = {}
    for i in range(7):
        day = (start_date + timedelta(days=i)).date()
        daily_counts[day.isoformat()] = {
            'total': 0,
            'critical': 0,
            'high': 0
        }
    
    severity_total = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    type_total = {}
    source_total = {}
    
    for alert in alerts:
        day_key = alert.timestamp.date().isoformat()
        if day_key in daily_counts:
            daily_counts[day_key]['total'] += 1
            if alert.level == AlertLevel.CRITICAL:
                daily_counts[day_key]['critical'] += 1
            elif alert.level == AlertLevel.HIGH:
                daily_counts[day_key]['high'] += 1
        
        severity_total[alert.level.name] += 1
        type_total[alert.alert_type] = type_total.get(alert.alert_type, 0) + 1
        source_total[alert.source_ip] = source_total.get(alert.source_ip, 0) + 1
    
    # Calculate trends
    first_half = sum(
        daily_counts[d]['total'] 
        for d in list(daily_counts.keys())[:3]
    )
    second_half = sum(
        daily_counts[d]['total'] 
        for d in list(daily_counts.keys())[4:]
    )
    
    if first_half > 0:
        trend_percentage = ((second_half - first_half) / first_half) * 100
    else:
        trend_percentage = 0
    
    if trend_percentage > 20:
        trend_direction = 'increasing'
    elif trend_percentage < -20:
        trend_direction = 'decreasing'
    else:
        trend_direction = 'stable'
    
    # Top threats
    top_types = sorted(type_total.items(), key=lambda x: x[1], reverse=True)[:10]
    top_sources = sorted(source_total.items(), key=lambda x: x[1], reverse=True)[:15]
    
    # Identify persistent threats (sources appearing multiple days)
    source_days = {}
    for alert in alerts:
        ip = alert.source_ip
        day = alert.timestamp.date().isoformat()
        if ip not in source_days:
            source_days[ip] = set()
        source_days[ip].add(day)
    
    persistent_threats = [
        {'ip': ip, 'days_active': len(days), 'total_alerts': source_total.get(ip, 0)}
        for ip, days in source_days.items()
        if len(days) >= 3  # Active 3+ days
    ]
    persistent_threats.sort(key=lambda x: x['total_alerts'], reverse=True)
    
    report = {
        'report_type': 'weekly',
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat()
        },
        'generated_at': datetime.utcnow().isoformat(),
        'summary': {
            'total_alerts': len(alerts),
            'daily_average': round(len(alerts) / 7, 1),
            'critical_alerts': severity_total['CRITICAL'],
            'high_alerts': severity_total['HIGH'],
            'unique_sources': len(source_total),
            'unique_alert_types': len(type_total)
        },
        'trend': {
            'direction': trend_direction,
            'percentage_change': round(trend_percentage, 1)
        },
        'daily_breakdown': daily_counts,
        'severity_breakdown': severity_total,
        'top_alert_types': [{'type': t, 'count': c} for t, c in top_types],
        'top_sources': [{'ip': ip, 'count': c} for ip, c in top_sources],
        'persistent_threats': persistent_threats[:10],
        'recommendations': _generate_weekly_recommendations(
            severity_total, 
            persistent_threats, 
            trend_direction,
            top_types
        )
    }
    
    return jsonify(report)


def _generate_weekly_recommendations(
    severity: dict, 
    persistent_threats: list, 
    trend: str,
    top_types: list
) -> list:
    """Generate weekly security recommendations"""
    recommendations = []
    
    # Trend-based recommendations
    if trend == 'increasing':
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Trend Analysis',
            'recommendation': 'Alert volume is increasing. Review recent infrastructure changes and consider additional monitoring resources.'
        })
    
    # Persistent threat recommendations
    if persistent_threats:
        threat_ips = [t['ip'] for t in persistent_threats[:5]]
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Threat Mitigation',
            'recommendation': f"Persistent threats detected from {len(persistent_threats)} sources. Consider permanent blocks for: {', '.join(threat_ips)}"
        })
    
    # High critical count
    if severity['CRITICAL'] > 50:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Security Posture',
            'recommendation': f"{severity['CRITICAL']} critical alerts this week. Conduct thorough security review and consider engaging external security assessment."
        })
    
    # Attack pattern recommendations
    attack_patterns = {
        'SQL': 'SQL injection',
        'XSS': 'cross-site scripting',
        'SCAN': 'reconnaissance/scanning',
        'BRUTE': 'brute force',
        'FLOOD': 'DoS/flooding'
    }
    
    for pattern, description in attack_patterns.items():
        pattern_count = sum(c for t, c in top_types if pattern in t.upper())
        if pattern_count > 100:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Attack Mitigation',
                'recommendation': f"High volume of {description} attempts ({pattern_count}). Review and strengthen relevant defenses."
            })
    
    if not recommendations:
        recommendations.append({
            'priority': 'LOW',
            'category': 'General',
            'recommendation': 'Security posture appears stable. Continue regular monitoring and scheduled security reviews.'
        })
    
    return recommendations


@api.route('/reports/custom', methods=['POST'])
@handle_errors
def generate_custom_report():
    """
    Generate a custom report with specified parameters.
    
    Request body:
    {
        "start_date": "2026-02-01T00:00:00",
        "end_date": "2026-02-14T23:59:59",
        "filters": {
            "levels": ["HIGH", "CRITICAL"],
            "types": ["ANOMALY:PORT_SCAN"],
            "source_ips": ["192.168.1.100"]
        },
        "include": {
            "summary": true,
            "timeline": true,
            "top_sources": true,
            "top_types": true,
            "raw_alerts": false
        }
    }
    """
    if not alert_service:
        return jsonify({'error': 'Alert service not initialized'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    # Parse date range
    try:
        start_date = datetime.fromisoformat(data.get('start_date', (datetime.utcnow() - timedelta(days=7)).isoformat()))
        end_date = datetime.fromisoformat(data.get('end_date', datetime.utcnow().isoformat()))
    except ValueError as e:
        return jsonify({'error': f'Invalid date format: {e}'}), 400
    
    # Get filters
    filters = data.get('filters', {})
    level_filter = filters.get('levels', [])
    type_filter = filters.get('types', [])
    source_filter = filters.get('source_ips', [])
    
    # Get include options
    include = data.get('include', {})
    include_summary = include.get('summary', True)
    include_timeline = include.get('timeline', True)
    include_top_sources = include.get('top_sources', True)
    include_top_types = include.get('top_types', True)
    include_raw_alerts = include.get('raw_alerts', False)
    
    # Fetch alerts
    all_alerts = alert_service.get_alerts(since=start_date, limit=100000)
    
    # Apply filters
    filtered_alerts = []
    for alert in all_alerts:
        if alert.timestamp > end_date:
            continue
        if level_filter and alert.level.name not in level_filter:
            continue
        if type_filter and not any(t in alert.alert_type for t in type_filter):
            continue
        if source_filter and alert.source_ip not in source_filter:
            continue
        filtered_alerts.append(alert)
    
    # Build report
    report = {
        'report_type': 'custom',
        'generated_at': datetime.utcnow().isoformat(),
        'parameters': {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'filters_applied': filters,
            'total_matching_alerts': len(filtered_alerts)
        }
    }
    
    # Summary section
    if include_summary:
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        status_counts = {'new': 0, 'acknowledged': 0, 'resolved': 0, 'false_positive': 0}
        unique_sources = set()
        unique_types = set()
        
        for alert in filtered_alerts:
            severity_counts[alert.level.name] += 1
            status_counts[alert.status.value] += 1
            unique_sources.add(alert.source_ip)
            unique_types.add(alert.alert_type)
        
        report['summary'] = {
            'total_alerts': len(filtered_alerts),
            'by_severity': severity_counts,
            'by_status': status_counts,
            'unique_sources': len(unique_sources),
            'unique_types': len(unique_types)
        }
    
    # Timeline section
    if include_timeline:
        # Determine appropriate interval based on date range
        date_range_days = (end_date - start_date).days
        if date_range_days <= 1:
            interval_minutes = 60  # Hourly
        elif date_range_days <= 7:
            interval_minutes = 360  # 6-hourly
        else:
            interval_minutes = 1440  # Daily
        
        timeline_buckets = {}
        for alert in filtered_alerts:
            bucket_time = alert.timestamp.replace(
                minute=(alert.timestamp.minute // interval_minutes) * interval_minutes if interval_minutes < 60 else 0,
                second=0,
                microsecond=0
            )
            if interval_minutes >= 1440:
                bucket_time = bucket_time.replace(hour=0)
            
            bucket_key = bucket_time.isoformat()
            if bucket_key not in timeline_buckets:
                timeline_buckets[bucket_key] = {'timestamp': bucket_key, 'count': 0}
            timeline_buckets[bucket_key]['count'] += 1
        
        report['timeline'] = {
            'interval_minutes': interval_minutes,
            'data': sorted(timeline_buckets.values(), key=lambda x: x['timestamp'])
        }
    
    # Top sources section
    if include_top_sources:
        source_counts = {}
        for alert in filtered_alerts:
            source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + 1
        
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        report['top_sources'] = [{'ip': ip, 'count': c} for ip, c in top_sources]
    
    # Top types section
    if include_top_types:
        type_counts = {}
        for alert in filtered_alerts:
            type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
        
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        report['top_types'] = [{'type': t, 'count': c} for t, c in top_types]
    
    # Raw alerts section (optional, can be large)
    if include_raw_alerts:
        max_raw = int(request.args.get('max_raw', 1000))
        report['alerts'] = [a.to_dict() for a in filtered_alerts[:max_raw]]
        if len(filtered_alerts) > max_raw:
            report['alerts_truncated'] = True
            report['alerts_total'] = len(filtered_alerts)
    
    return jsonify(report)


# =============================================================================
# Error Handlers
# =============================================================================

@api.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400


@api.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': str(error)}), 404


@api.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500