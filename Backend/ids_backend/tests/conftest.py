"""
Pytest configuration and shared fixtures for IDS tests.
"""

import pytest
import os
import tempfile
from datetime import datetime, timedelta

# Set testing environment
os.environ['TESTING'] = 'true'


@pytest.fixture(scope='session')
def temp_log_dir():
    """Create a temporary directory for test logs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_packet_data():
    """Sample packet data for testing"""
    return {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
        'size': 100,
        'flags': {
            'syn': False,
            'ack': True,
            'fin': False,
            'rst': False,
            'psh': True,
            'urg': False
        }
    }


@pytest.fixture
def malicious_packet_data():
    """Sample malicious packet data for testing"""
    return {
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
        'src_port': 45678,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': b"GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1",
        'size': 150,
        'flags': {
            'syn': False,
            'ack': True,
            'fin': False,
            'rst': False,
            'psh': True,
            'urg': False
        }
    }


@pytest.fixture
def xss_packet_data():
    """Sample XSS attack packet data"""
    return {
        'src_ip': '10.0.0.51',
        'dst_ip': '192.168.1.1',
        'src_port': 45679,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
        'size': 120,
        'flags': {
            'syn': False,
            'ack': True,
            'fin': False,
            'rst': False,
            'psh': True,
            'urg': False
        }
    }


@pytest.fixture
def path_traversal_packet_data():
    """Sample path traversal attack packet data"""
    return {
        'src_ip': '10.0.0.52',
        'dst_ip': '192.168.1.1',
        'src_port': 45680,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': b"GET /files/../../../etc/passwd HTTP/1.1",
        'size': 100,
        'flags': {
            'syn': False,
            'ack': True,
            'fin': False,
            'rst': False,
            'psh': True,
            'urg': False
        }
    }


@pytest.fixture
def syn_flood_packets():
    """Generate multiple SYN packets for flood testing"""
    packets = []
    for i in range(50):
        packets.append({
            'src_ip': '10.0.0.100',
            'dst_ip': '192.168.1.1',
            'src_port': 50000 + i,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': b'',
            'size': 64,
            'flags': {
                'syn': True,
                'ack': False,
                'fin': False,
                'rst': False,
                'psh': False,
                'urg': False
            }
        })
    return packets


@pytest.fixture
def port_scan_packets():
    """Generate packets for port scan testing"""
    packets = []
    for port in range(1, 101):  # Scan 100 ports
        packets.append({
            'src_ip': '10.0.0.200',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'tcp',
            'payload': b'',
            'size': 64,
            'flags': {
                'syn': True,
                'ack': False,
                'fin': False,
                'rst': False,
                'psh': False,
                'urg': False
            }
        })
    return packets


@pytest.fixture
def sample_alerts():
    """Generate sample alerts for testing"""
    from models.alert import Alert, AlertLevel, AlertStatus
    
    alerts = []
    
    # Various alert levels
    alerts.append(Alert(
        alert_type='SIGNATURE:SQL_Injection',
        source_ip='192.168.1.100',
        description='SQL injection attempt detected',
        level=AlertLevel.HIGH,
        destination_ip='10.0.0.1',
        destination_port=80
    ))
    
    alerts.append(Alert(
        alert_type='ANOMALY:PORT_SCAN',
        source_ip='192.168.1.101',
        description='Port scan detected from source',
        level=AlertLevel.MEDIUM,
        destination_ip='10.0.0.1',
        destination_port=None
    ))
    
    alerts.append(Alert(
        alert_type='ANOMALY:SYN_FLOOD',
        source_ip='192.168.1.102',
        description='Potential SYN flood attack',
        level=AlertLevel.CRITICAL,
        destination_ip='10.0.0.1',
        destination_port=80
    ))
    
    alerts.append(Alert(
        alert_type='SIGNATURE:XSS_Attempt',
        source_ip='192.168.1.103',
        description='Cross-site scripting attempt',
        level=AlertLevel.MEDIUM,
        destination_ip='10.0.0.1',
        destination_port=443
    ))
    
    alerts.append(Alert(
        alert_type='ANOMALY:BRUTE_FORCE',
        source_ip='192.168.1.104',
        description='Brute force authentication attempt',
        level=AlertLevel.HIGH,
        destination_ip='10.0.0.1',
        destination_port=22
    ))
    
    return alerts


@pytest.fixture
def sample_rules():
    """Generate sample detection rules for testing"""
    from models.rule import DetectionRule, RuleAction
    
    rules = []
    
    rules.append(DetectionRule(
        name='Test SQL Injection',
        pattern=r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*')",
        action=RuleAction.ALERT,
        alert_level='HIGH',
        description='Detects SQL injection patterns',
        tags=['sqli', 'injection']
    ))
    
    rules.append(DetectionRule(
        name='Test XSS',
        pattern=r"(<script|javascript:|on\w+\s*=)",
        action=RuleAction.ALERT,
        alert_level='MEDIUM',
        description='Detects XSS patterns',
        tags=['xss', 'injection']
    ))
    
    rules.append(DetectionRule(
        name='Test Path Traversal',
        pattern=r"(\.\.\/|\.\.\\|%2e%2e%2f)",
        action=RuleAction.ALERT,
        alert_level='HIGH',
        description='Detects path traversal',
        tags=['lfi', 'traversal']
    ))
    
    return rules


@pytest.fixture
def mock_alert_service(temp_log_dir):
    """Create a mock alert service for testing"""
    from services.alert_service import AlertService
    
    log_file = os.path.join(temp_log_dir, 'test_alerts.log')
    service = AlertService(log_file=log_file, max_alerts=1000)
    return service


@pytest.fixture
def mock_traffic_monitor(mock_alert_service):
    """Create a mock traffic monitor for testing"""
    from services.traffic_monitor import TrafficMonitor
    
    monitor = TrafficMonitor(
        alert_service=mock_alert_service,
        interface='lo',  # Loopback for testing
        use_anomaly_detection=True,
        use_signature_detection=True
    )
    return monitor


@pytest.fixture
def populated_alert_service(mock_alert_service, sample_alerts):
    """Alert service pre-populated with sample alerts"""
    for alert in sample_alerts:
        mock_alert_service.add_alert(alert, bypass_rate_limit=True)
    return mock_alert_service


# Helper functions available to all tests

def generate_random_ip():
    """Generate a random IP address"""
    import random
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_packet_batch(count: int, src_ip: str = None, dst_port: int = 80):
    """Generate a batch of packets for testing"""
    import random
    
    packets = []
    for i in range(count):
        packets.append({
            'src_ip': src_ip or generate_random_ip(),
            'dst_ip': '192.168.1.1',
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': 'tcp',
            'payload': b'test payload',
            'size': random.randint(64, 1500),
            'flags': {
                'syn': False,
                'ack': True,
                'fin': False,
                'rst': False,
                'psh': True,
                'urg': False
            }
        })
    return packets


# Make helper functions available as fixtures
@pytest.fixture
def random_ip_generator():
    """Fixture that returns the random IP generator function"""
    return generate_random_ip


@pytest.fixture
def packet_batch_generator():
    """Fixture that returns the packet batch generator function"""
    return generate_packet_batch


# Pytest configuration hooks

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_root: marks tests that require root privileges"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers"""
    # Skip tests requiring root if not running as root
    if os.geteuid() != 0:
        skip_root = pytest.mark.skip(reason="Test requires root privileges")
        for item in items:
            if "requires_root" in item.keywords:
                item.add_marker(skip_root)