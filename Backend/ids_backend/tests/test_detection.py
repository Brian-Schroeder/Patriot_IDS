import pytest
from datetime import datetime, timedelta

from detection.packet_analyzer import PacketAnalyzer, PacketInfo
from detection.rule_engine import RuleEngine, DetectionRule, RuleAction
from detection.anomaly_detector import AnomalyDetector
from models.alert import AlertLevel


class TestPacketAnalyzer:
    """Tests for PacketAnalyzer"""
    
    def setup_method(self):
        self.analyzer = PacketAnalyzer()
    
    def test_analyze_basic_packet(self):
        packet_data = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': b'GET / HTTP/1.1',
            'size': 100,
            'flags': {'syn': True, 'ack': False}
        }
        
        result = self.analyzer.analyze(packet_data)
        
        assert isinstance(result, PacketInfo)
        assert result.source_ip == '192.168.1.100'
        assert result.destination_ip == '10.0.0.1'
        assert result.protocol == 'tcp'
    
    def test_check_suspicious_port(self):
        assert self.analyzer.check_suspicious_port(22) == 'SSH'
        assert self.analyzer.check_suspicious_port(3389) == 'RDP'
        assert self.analyzer.check_suspicious_port(8080) is None
    
    def test_check_malicious_payload(self):
        # SQL injection
        payload = b"SELECT * FROM users WHERE id=1 OR 1=1"
        result = self.analyzer.check_malicious_payload(payload)
        assert 'OR 1=1' in result
        
        # Path traversal
        payload = b"GET /../../../etc/passwd HTTP/1.1"
        result = self.analyzer.check_malicious_payload(payload)
        assert '/etc/passwd' in result
        
        # Clean payload
        payload = b"GET /index.html HTTP/1.1"
        result = self.analyzer.check_malicious_payload(payload)
        assert len(result) == 0
    
    def test_check_packet_anomalies(self):
        # SYN+FIN (invalid)
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.1',
            destination_ip='10.0.0.1',
            source_port=12345,
            destination_port=80,
            protocol='tcp',
            payload=b'',
            size=64,
            flags={'syn': True, 'fin': True, 'ack': False, 'rst': False, 'psh': False, 'urg': False}
        )
        
        anomalies = self.analyzer.check_packet_anomalies(packet)
        assert any('SYN+FIN' in a for a in anomalies)
    
    def test_check_xmas_scan(self):
        # XMAS scan (FIN+PSH+URG)
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.1',
            destination_ip='10.0.0.1',
            source_port=12345,
            destination_port=80,
            protocol='tcp',
            payload=b'',
            size=64,
            flags={'syn': False, 'fin': True, 'ack': False, 'rst': False, 'psh': True, 'urg': True}
        )
        
        anomalies = self.analyzer.check_packet_anomalies(packet)
        assert any('XMAS' in a for a in anomalies)
    
    def test_check_null_scan(self):
        # NULL scan (no flags)
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.1',
            destination_ip='10.0.0.1',
            source_port=12345,
            destination_port=80,
            protocol='tcp',
            payload=b'',
            size=64,
            flags={'syn': False, 'fin': False, 'ack': False, 'rst': False, 'psh': False, 'urg': False}
        )
        
        anomalies = self.analyzer.check_packet_anomalies(packet)
        assert any('NULL' in a for a in anomalies)
    
    def test_oversized_packet(self):
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.1',
            destination_ip='10.0.0.1',
            source_port=12345,
            destination_port=80,
            protocol='tcp',
            payload=b'',
            size=70000,  # Oversized
            flags={}
        )
        
        anomalies = self.analyzer.check_packet_anomalies(packet)
        assert any('Oversized' in a for a in anomalies)
    
    def test_get_stats(self):
        # Process some packets
        for i in range(5):
            self.analyzer.analyze({
                'src_ip': f'192.168.1.{i}',
                'dst_ip': '10.0.0.1',
                'protocol': 'tcp',
                'payload': b'normal traffic',
                'size': 100,
                'flags': {}
            })
        
        stats = self.analyzer.get_stats()
        assert stats['total_packets'] == 5


class TestRuleEngine:
    """Tests for RuleEngine"""
    
    def setup_method(self):
        self.engine = RuleEngine()
    
    def test_default_rules_loaded(self):
        rules = self.engine.get_all_rules()
        assert len(rules) > 0
        
        # Check for expected default rules
        rule_names = [r.name for r in rules]
        assert 'SQL Injection Attempt' in rule_names
        assert 'XSS Attempt' in rule_names
    
    def test_add_custom_rule(self):
        rule = DetectionRule(
            name='Test Rule',
            pattern=r'test_pattern',
            action=RuleAction.ALERT,
            alert_level='MEDIUM',
            description='A test rule'
        )
        
        rule_id = self.engine.add_rule(rule)
        assert rule_id is not None
        
        retrieved = self.engine.get_rule(rule_id)
        assert retrieved is not None
        assert retrieved.name == 'Test Rule'
    
    def test_remove_rule(self):
        rule = DetectionRule(
            name='Temporary Rule',
            pattern=r'temp',
            action=RuleAction.ALERT,
            alert_level='LOW'
        )
        
        rule_id = self.engine.add_rule(rule)
        assert self.engine.get_rule(rule_id) is not None
        
        success = self.engine.remove_rule(rule_id)
        assert success is True
        assert self.engine.get_rule(rule_id) is None
    
    def test_toggle_rule(self):
        rule = DetectionRule(
            name='Toggle Test',
            pattern=r'toggle',
            action=RuleAction.ALERT,
            alert_level='LOW',
            enabled=True
        )
        
        rule_id = self.engine.add_rule(rule)
        
        # Disable
        self.engine.toggle_rule(rule_id, False)
        assert self.engine.get_rule(rule_id).enabled is False
        
        # Enable
        self.engine.toggle_rule(rule_id, True)
        assert self.engine.get_rule(rule_id).enabled is True
    
    def test_evaluate_sql_injection(self):
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='tcp',
            payload=b"GET /search?q=1' OR '1'='1 HTTP/1.1",
            size=100,
            flags={}
        )
        
        alerts = self.engine.evaluate(packet)
        assert len(alerts) > 0
        assert any('SQL' in a.alert_type for a in alerts)
    
    def test_evaluate_xss(self):
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='tcp',
            payload=b"GET /page?name=<script>alert('xss')</script> HTTP/1.1",
            size=100,
            flags={}
        )
        
        alerts = self.engine.evaluate(packet)
        assert len(alerts) > 0
        assert any('XSS' in a.alert_type for a in alerts)
    
    def test_evaluate_path_traversal(self):
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='tcp',
            payload=b"GET /files/../../../etc/passwd HTTP/1.1",
            size=100,
            flags={}
        )
        
        alerts = self.engine.evaluate(packet)
        assert len(alerts) > 0
        assert any('Traversal' in a.alert_type or 'Sensitive' in a.alert_type for a in alerts)
    
    def test_evaluate_clean_traffic(self):
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='tcp',
            payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            size=100,
            flags={}
        )
        
        alerts = self.engine.evaluate(packet)
        assert len(alerts) == 0
    
    def test_disabled_rule_not_evaluated(self):
        # Add and disable a rule
        rule = DetectionRule(
            name='Disabled Rule',
            pattern=r'disabled_test_pattern',
            action=RuleAction.ALERT,
            alert_level='HIGH',
            enabled=False
        )
        self.engine.add_rule(rule)
        
        packet = PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip='192.168.1.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='tcp',
            payload=b"disabled_test_pattern",
            size=100,
            flags={}
        )
        
        alerts = self.engine.evaluate(packet)
        assert not any('Disabled Rule' in a.metadata.get('rule_name', '') for a in alerts)


class TestAnomalyDetector:
    """Tests for AnomalyDetector"""
    
    def setup_method(self):
        self.detector = AnomalyDetector(time_window_minutes=1)
        # Set lower thresholds for testing
        self.detector.update_thresholds({
            'connections_per_ip': 10,
            'port_scan_threshold': 5,
            'syn_flood_threshold': 20,
            'failed_auth_threshold': 3
        })
    
    def _create_packet(self, src_ip='192.168.1.100', dst_port=80, flags=None):
        return PacketInfo(
            timestamp=datetime.utcnow(),
            source_ip=src_ip,
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=dst_port,
            protocol='tcp',
            payload=b'test',
            size=100,
            flags=flags or {'syn': False, 'ack': True}
        )
    
    def test_connection_flood_detection(self):
        src_ip = '192.168.1.100'
        alerts = []
        
        # Generate many connections from same IP
        for i in range(15):
            packet = self._create_packet(src_ip=src_ip, dst_port=80)
            alerts.extend(self.detector.analyze(packet))
        
        # Should detect connection flood
        flood_alerts = [a for a in alerts if 'CONNECTION_FLOOD' in a.alert_type]
        assert len(flood_alerts) > 0
    
    def test_port_scan_detection(self):
        src_ip = '192.168.1.100'
        alerts = []
        
        # Scan multiple ports
        for port in range(20, 30):  # 10 different ports
            packet = self._create_packet(src_ip=src_ip, dst_port=port)
            alerts.extend(self.detector.analyze(packet))
        
        # Should detect port scan
        scan_alerts = [a for a in alerts if 'PORT_SCAN' in a.alert_type]
        assert len(scan_alerts) > 0
    
    def test_syn_flood_detection(self):
        src_ip = '192.168.1.100'
        alerts = []
        
        # Generate many SYN packets
        for i in range(25):
            packet = PacketInfo(
                timestamp=datetime.utcnow(),
                source_ip=src_ip,
                destination_ip='10.0.0.1',
                source_port=50000 + i,
                destination_port=80,
                protocol='tcp',
                payload=b'',
                size=64,
                flags={'syn': True, 'ack': False, 'fin': False, 'rst': False, 'psh': False, 'urg': False}
            )
            alerts.extend(self.detector.analyze(packet))
        
        # Should detect SYN flood
        syn_alerts = [a for a in alerts if 'SYN_FLOOD' in a.alert_type]
        assert len(syn_alerts) > 0
    
    def test_brute_force_detection(self):
        src_ip = '192.168.1.100'
        
        # Record failed auth attempts
        for i in range(5):
            self.detector.record_failed_auth(src_ip)
        
        # Analyze a packet to trigger check
        packet = self._create_packet(src_ip=src_ip)
        alerts = self.detector.analyze(packet)
        
        # Should detect brute force
        brute_alerts = [a for a in alerts if 'BRUTE_FORCE' in a.alert_type]
        assert len(brute_alerts) > 0
    
    def test_normal_traffic_no_alerts(self):
        # Generate normal traffic from multiple IPs
        alerts = []
        for i in range(5):
            for ip_suffix in range(1, 4):
                packet = self._create_packet(
                    src_ip=f'192.168.1.{ip_suffix}',
                    dst_port=80
                )
                alerts.extend(self.detector.analyze(packet))
        
        # Should not trigger any alerts
        assert len(alerts) == 0
    
    def test_update_thresholds(self):
        new_thresholds = {
            'connections_per_ip': 500,
            'port_scan_threshold': 100
        }
        
        self.detector.update_thresholds(new_thresholds)
        
        assert self.detector.thresholds['connections_per_ip'] == 500
        assert self.detector.thresholds['port_scan_threshold'] == 100
    
    def test_get_statistics(self):
        # Generate some traffic
        for i in range(10):
            packet = self._create_packet(
                src_ip=f'192.168.1.{i % 3}',
                dst_port=80 + (i % 5)
            )
            self.detector.analyze(packet)
        
        stats = self.detector.get_statistics()
        
        assert 'baseline' in stats
        assert 'current_window' in stats
        assert 'thresholds' in stats
        assert stats['baseline']['sample_count'] > 0
    
    def test_multiple_ips_no_flood(self):
        """Multiple IPs with moderate traffic should not trigger flood alert"""
        alerts = []
        
        # 5 connections each from 10 different IPs
        for ip_suffix in range(10):
            for _ in range(5):
                packet = self._create_packet(
                    src_ip=f'192.168.1.{ip_suffix}',
                    dst_port=80
                )
                alerts.extend(self.detector.analyze(packet))
        
        # Should not trigger connection flood (threshold is 10 per IP)
        flood_alerts = [a for a in alerts if 'CONNECTION_FLOOD' in a.alert_type]
        assert len(flood_alerts) == 0
    
    def test_baseline_learning(self):
        """Test that baseline statistics are updated over time"""
        initial_sample_count = self.detector.baseline.sample_count
        
        # Generate traffic
        for i in range(50):
            packet = self._create_packet(dst_port=80)
            self.detector.analyze(packet)
        
        # Baseline should have more samples
        assert self.detector.baseline.sample_count > initial_sample_count


class TestDetectionRuleModel:
    """Tests for DetectionRule model"""
    
    def test_rule_creation(self):
        rule = DetectionRule(
            name='Test Rule',
            pattern=r'\btest\b',
            action=RuleAction.ALERT,
            alert_level='HIGH',
            description='Test description',
            tags=['test', 'example']
        )
        
        assert rule.name == 'Test Rule'
        assert rule.enabled is True
        assert rule.id is not None
    
    def test_rule_pattern_matching(self):
        rule = DetectionRule(
            name='Pattern Test',
            pattern=r'password\s*=\s*["\']?\w+',
            action=RuleAction.ALERT,
            alert_level='HIGH'
        )
        
        assert rule.matches_payload('password=secret123') is True
        assert rule.matches_payload('password = "mypass"') is True
        assert rule.matches_payload('username=admin') is False
    
    def test_rule_to_dict(self):
        rule = DetectionRule(
            name='Dict Test',
            pattern=r'test',
            action=RuleAction.ALERT,
            alert_level='MEDIUM',
            tags=['tag1', 'tag2']
        )
        
        rule_dict = rule.to_dict()
        
        assert rule_dict['name'] == 'Dict Test'
        assert rule_dict['alert_level'] == 'MEDIUM'
        assert rule_dict['action'] == 'alert'
        assert 'tag1' in rule_dict['tags']
    
    def test_invalid_regex_pattern(self):
        """Rule with invalid regex should handle gracefully"""
        rule = DetectionRule(
            name='Invalid Regex',
            pattern=r'[invalid(regex',  # Invalid regex
            action=RuleAction.ALERT,
            alert_level='LOW'
        )
        
        # Should not raise, but pattern matching should return False
        assert rule.matches_payload('any text') is False


class TestIntegration:
    """Integration tests for detection components"""
    
    def setup_method(self):
        self.analyzer = PacketAnalyzer()
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector(time_window_minutes=1)
    
    def test_full_detection_pipeline(self):
        """Test complete detection pipeline with malicious packet"""
        # Simulate a malicious request
        packet_data = {
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
            'src_port': 45678,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': b"GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1",
            'size': 150,
            'flags': {'syn': False, 'ack': True, 'fin': False, 'rst': False, 'psh': True, 'urg': False}
        }
        
        # Analyze packet
        packet_info = self.analyzer.analyze(packet_data)
        
        # Check for malicious payload
        malicious = self.analyzer.check_malicious_payload(packet_info.payload)
        assert len(malicious) > 0
        
        # Run rule engine
        rule_alerts = self.rule_engine.evaluate(packet_info)
        assert len(rule_alerts) > 0
        
        # Verify alert details
        sql_alerts = [a for a in rule_alerts if 'SQL' in a.alert_type]
        assert len(sql_alerts) > 0
        assert sql_alerts[0].source_ip == '10.0.0.50'
    
    def test_combined_attack_detection(self):
        """Test detection of combined attack patterns"""
        # Attacker doing recon + exploitation
        attacker_ip = '10.0.0.100'
        all_alerts = []
        
        # Phase 1: Port scanning
        for port in range(20, 35):
            packet_data = {
                'src_ip': attacker_ip,
                'dst_ip': '192.168.1.1',
                'src_port': 50000,
                'dst_port': port,
                'protocol': 'tcp',
                'payload': b'',
                'size': 64,
                'flags': {'syn': True, 'ack': False}
            }
            packet_info = self.analyzer.analyze(packet_data)
            all_alerts.extend(self.anomaly_detector.analyze(packet_info))
        
        # Phase 2: SQL injection attempt
        packet_data = {
            'src_ip': attacker_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 50001,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': b"POST /login HTTP/1.1\r\n\r\nusername=admin'--&password=x",
            'size': 200,
            'flags': {'syn': False, 'ack': True, 'psh': True}
        }
        packet_info = self.analyzer.analyze(packet_data)
        all_alerts.extend(self.rule_engine.evaluate(packet_info))
        
        # Should have both scan and SQL injection alerts
        scan_alerts = [a for a in all_alerts if 'SCAN' in a.alert_type]
        sqli_alerts = [a for a in all_alerts if 'SQL' in a.alert_type]
        
        assert len(scan_alerts) > 0, "Should detect port scan"
        assert len(sqli_alerts) > 0, "Should detect SQL injection"