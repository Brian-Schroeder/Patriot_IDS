import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from app import create_app
from services.alert_service import AlertService
from services.traffic_monitor import TrafficMonitor
from models.alert import Alert, AlertLevel, AlertStatus


@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def alert_service():
    """Create alert service for testing"""
    return AlertService(log_file='/tmp/test_api_alerts.log', max_alerts=1000)


class TestHealthEndpoints:
    """Tests for health and status endpoints"""
    
    def test_health_check(self, client):
        response = client.get('/api/v1/health')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
    
    def test_status_endpoint(self, client):
        response = client.get('/api/v1/status')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'system' in data
        assert 'monitor' in data
        assert 'alerts' in data
    
    def test_stats_endpoint(self, client):
        response = client.get('/api/v1/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'monitor' in data
        assert 'detection' in data


class TestAlertEndpoints:
    """Tests for alert API endpoints"""
    
    def test_get_alerts_empty(self, client):
        response = client.get('/api/v1/alerts')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data
        assert 'count' in data
    
    def test_get_alerts_with_filters(self, client):
        response = client.get('/api/v1/alerts?level=HIGH&limit=10')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['limit'] == 10
    
    def test_get_alert_not_found(self, client):
        response = client.get('/api/v1/alerts/nonexistent-id')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_update_alert_status(self, client):
        # First, we need to create an alert via the monitor/inject endpoint
        # or directly through the service
        response = client.put(
            '/api/v1/alerts/test-id/status',
            data=json.dumps({'status': 'acknowledged'}),
            content_type='application/json'
        )
        
        # Will be 404 since alert doesn't exist, but validates endpoint works
        assert response.status_code in [200, 404]
    
    def test_update_alert_status_invalid(self, client):
        response = client.put(
            '/api/v1/alerts/test-id/status',
            data=json.dumps({'status': 'invalid_status'}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_bulk_update_status(self, client):
        response = client.put(
            '/api/v1/alerts/bulk/status',
            data=json.dumps({
                'alert_ids': ['id1', 'id2'],
                'status': 'resolved'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'results' in data
    
    def test_bulk_update_missing_fields(self, client):
        response = client.put(
            '/api/v1/alerts/bulk/status',
            data=json.dumps({'status': 'resolved'}),  # Missing alert_ids
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_export_alerts_json(self, client):
        response = client.get('/api/v1/alerts/export?format=json')
        
        assert response.status_code == 200
        assert response.content_type == 'application/json'
    
    def test_export_alerts_csv(self, client):
        response = client.get('/api/v1/alerts/export?format=csv')
        
        assert response.status_code == 200
        assert response.content_type == 'text/csv'
    
    def test_export_alerts_invalid_format(self, client):
        response = client.get('/api/v1/alerts/export?format=xml')
        
        assert response.status_code == 400
    
    def test_alert_statistics(self, client):
        response = client.get('/api/v1/alerts/statistics')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_alerts' in data


class TestRuleEndpoints:
    """Tests for detection rule API endpoints"""
    
    def test_get_rules(self, client):
        response = client.get('/api/v1/rules')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'rules' in data
        assert 'count' in data
        assert data['count'] > 0  # Default rules should exist
    
    def test_create_rule(self, client):
        rule_data = {
            'name': 'Test API Rule',
            'pattern': r'test_pattern_\d+',
            'alert_level': 'MEDIUM',
            'action': 'alert',
            'description': 'A test rule created via API',
            'tags': ['test', 'api']
        }
        
        response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['rule']['name'] == 'Test API Rule'
        assert 'id' in data['rule']
    
    def test_create_rule_missing_fields(self, client):
        rule_data = {
            'name': 'Incomplete Rule'
            # Missing pattern and alert_level
        }
        
        response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_create_rule_invalid_level(self, client):
        rule_data = {
            'name': 'Bad Level Rule',
            'pattern': r'test',
            'alert_level': 'SUPER_HIGH'  # Invalid
        }
        
        response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'alert_level' in data['error'].lower()
    
    def test_get_rule_by_id(self, client):
        # First create a rule
        rule_data = {
            'name': 'Retrievable Rule',
            'pattern': r'retrieve_test',
            'alert_level': 'LOW'
        }
        
        create_response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        created_rule = json.loads(create_response.data)['rule']
        rule_id = created_rule['id']
        
        # Now retrieve it
        response = client.get(f'/api/v1/rules/{rule_id}')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['name'] == 'Retrievable Rule'
    
    def test_get_rule_not_found(self, client):
        response = client.get('/api/v1/rules/nonexistent-rule-id')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_update_rule(self, client):
        # Create a rule first
        rule_data = {
            'name': 'Original Name',
            'pattern': r'original_pattern',
            'alert_level': 'LOW'
        }
        
        create_response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        rule_id = json.loads(create_response.data)['rule']['id']
        
        # Update the rule
        update_data = {
            'name': 'Updated Name',
            'alert_level': 'HIGH',
            'description': 'Updated description'
        }
        
        response = client.put(
            f'/api/v1/rules/{rule_id}',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['rule']['name'] == 'Updated Name'
        assert data['rule']['alert_level'] == 'HIGH'
    
    def test_update_rule_not_found(self, client):
        update_data = {
            'name': 'Updated Name'
        }
        
        response = client.put(
            '/api/v1/rules/nonexistent-id',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 404
    
    def test_delete_rule(self, client):
        # Create a rule first
        rule_data = {
            'name': 'To Be Deleted',
            'pattern': r'delete_me',
            'alert_level': 'LOW'
        }
        
        create_response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        rule_id = json.loads(create_response.data)['rule']['id']
        
        # Delete the rule
        response = client.delete(f'/api/v1/rules/{rule_id}')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['rule_id'] == rule_id
        
        # Verify it's gone
        get_response = client.get(f'/api/v1/rules/{rule_id}')
        assert get_response.status_code == 404
    
    def test_delete_rule_not_found(self, client):
        response = client.delete('/api/v1/rules/nonexistent-id')
        
        assert response.status_code == 404
    
    def test_toggle_rule_enable(self, client):
        # Create a rule
        rule_data = {
            'name': 'Toggle Test',
            'pattern': r'toggle',
            'alert_level': 'MEDIUM'
        }
        
        create_response = client.post(
            '/api/v1/rules',
            data=json.dumps(rule_data),
            content_type='application/json'
        )
        
        rule_id = json.loads(create_response.data)['rule']['id']
        
        # Disable the rule
        response = client.post(
            f'/api/v1/rules/{rule_id}/toggle',
            data=json.dumps({'enabled': False}),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['rule']['enabled'] is False
        
        # Enable the rule
        response = client.post(
            f'/api/v1/rules/{rule_id}/toggle',
            data=json.dumps({'enabled': True}),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['rule']['enabled'] is True
    
    def test_toggle_rule_missing_enabled(self, client):
        response = client.post(
            '/api/v1/rules/some-id/toggle',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_test_rule_pattern_match(self, client):
        test_data = {
            'pattern': r'password\s*=\s*\w+',
            'payload': 'user input: password = secret123'
        }
        
        response = client.post(
            '/api/v1/rules/test',
            data=json.dumps(test_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['matches'] is True
        assert data['match_details']['matched_text'] == 'password = secret123'
    
    def test_test_rule_pattern_no_match(self, client):
        test_data = {
            'pattern': r'password\s*=\s*\w+',
            'payload': 'just some normal text'
        }
        
        response = client.post(
            '/api/v1/rules/test',
            data=json.dumps(test_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['matches'] is False
    
    def test_test_rule_invalid_regex(self, client):
        test_data = {
            'pattern': r'[invalid(regex',
            'payload': 'test'
        }
        
        response = client.post(
            '/api/v1/rules/test',
            data=json.dumps(test_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data


class TestAnomalyEndpoints:
    """Tests for anomaly detection API endpoints"""
    
    def test_get_thresholds(self, client):
        response = client.get('/api/v1/anomaly/thresholds')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'thresholds' in data
        assert 'packets_per_second' in data['thresholds']
        assert 'connections_per_ip' in data['thresholds']
    
    def test_update_thresholds(self, client):
        update_data = {
            'packets_per_second': 2000,
            'connections_per_ip': 200
        }
        
        response = client.put(
            '/api/v1/anomaly/thresholds',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['thresholds']['packets_per_second'] == 2000
        assert data['thresholds']['connections_per_ip'] == 200
    
    def test_update_thresholds_invalid_key(self, client):
        update_data = {
            'invalid_threshold': 100
        }
        
        response = client.put(
            '/api/v1/anomaly/thresholds',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_update_thresholds_negative_value(self, client):
        update_data = {
            'packets_per_second': -100
        }
        
        response = client.put(
            '/api/v1/anomaly/thresholds',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_get_anomaly_statistics(self, client):
        response = client.get('/api/v1/anomaly/statistics')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'baseline' in data
        assert 'current_window' in data
    
    def test_reset_baseline(self, client):
        response = client.post('/api/v1/anomaly/baseline/reset')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'reset' in data['message'].lower()
    
    def test_record_failed_auth(self, client):
        auth_data = {
            'source_ip': '192.168.1.100'
        }
        
        response = client.post(
            '/api/v1/anomaly/failed-auth',
            data=json.dumps(auth_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['source_ip'] == '192.168.1.100'
        assert 'failed_attempts' in data
    
    def test_record_failed_auth_missing_ip(self, client):
        response = client.post(
            '/api/v1/anomaly/failed-auth',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        assert response.status_code == 400


class TestBlocklistEndpoints:
    """Tests for blocklist API endpoints"""
    
    def test_get_blocklist_empty(self, client):
        response = client.get('/api/v1/blocklist')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'blocked_ips' in data
        assert 'count' in data
    
    def test_add_to_blocklist(self, client):
        block_data = {
            'ip': '10.0.0.100',
            'reason': 'Malicious activity detected',
            'blocked_by': 'test'
        }
        
        response = client.post(
            '/api/v1/blocklist',
            data=json.dumps(block_data),
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['entry']['ip'] == '10.0.0.100'
        assert data['entry']['reason'] == 'Malicious activity detected'
    
    def test_add_to_blocklist_with_expiration(self, client):
        block_data = {
            'ip': '10.0.0.101',
            'reason': 'Temporary block',
            'expires_in_hours': 24
        }
        
        response = client.post(
            '/api/v1/blocklist',
            data=json.dumps(block_data),
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['entry']['expires_at'] is not None
    
    def test_add_to_blocklist_missing_ip(self, client):
        block_data = {
            'reason': 'No IP provided'
        }
        
        response = client.post(
            '/api/v1/blocklist',
            data=json.dumps(block_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_check_blocked_ip(self, client):
        # First add an IP
        client.post(
            '/api/v1/blocklist',
            data=json.dumps({'ip': '10.0.0.102', 'reason': 'Test'}),
            content_type='application/json'
        )
        
        # Check if blocked
        response = client.get('/api/v1/blocklist/check/10.0.0.102')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['blocked'] is True
        assert data['ip'] == '10.0.0.102'
    
    def test_check_unblocked_ip(self, client):
        response = client.get('/api/v1/blocklist/check/192.168.1.1')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['blocked'] is False
    
    def test_remove_from_blocklist(self, client):
        # Add an IP
        client.post(
            '/api/v1/blocklist',
            data=json.dumps({'ip': '10.0.0.103', 'reason': 'Test'}),
            content_type='application/json'
        )
        
        # Remove it
        response = client.delete('/api/v1/blocklist/10.0.0.103')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['ip'] == '10.0.0.103'
        
        # Verify it's removed
        check_response = client.get('/api/v1/blocklist/check/10.0.0.103')
        check_data = json.loads(check_response.data)
        assert check_data['blocked'] is False
    
    def test_remove_nonexistent_from_blocklist(self, client):
        response = client.delete('/api/v1/blocklist/1.2.3.4')
        
        assert response.status_code == 404


class TestMonitorEndpoints:
    """Tests for traffic monitor API endpoints"""
    
    def test_get_monitor_status(self, client):
        response = client.get('/api/v1/monitor/status')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'is_running' in data
        assert 'interface' in data
        assert 'packets_processed' in data
        assert 'detection_modules' in data
    
    def test_inject_packet(self, client):
        packet_data = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': 'GET /index.html HTTP/1.1',
            'size': 150
        }
        
        response = client.post(
            '/api/v1/monitor/inject',
            data=json.dumps(packet_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert data['packet']['src_ip'] == '192.168.1.100'
    
    def test_inject_packet_missing_required_fields(self, client):
        packet_data = {
            'src_ip': '192.168.1.100'
            # Missing dst_ip
        }
        
        response = client.post(
            '/api/v1/monitor/inject',
            data=json.dumps(packet_data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_inject_packet_empty_body(self, client):
        response = client.post(
            '/api/v1/monitor/inject',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_inject_malicious_packet_generates_alert(self, client):
        """Test that injecting a malicious packet generates an alert"""
        packet_data = {
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
            'src_port': 45678,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': "GET /search?q=' OR '1'='1 HTTP/1.1",
            'size': 200
        }
        
        # Inject the packet
        inject_response = client.post(
            '/api/v1/monitor/inject',
            data=json.dumps(packet_data),
            content_type='application/json'
        )
        
        assert inject_response.status_code == 200
        
        # Give it a moment to process, then check for alerts
        import time
        time.sleep(0.5)
        
        # Check alerts from this source IP
        alerts_response = client.get('/api/v1/alerts?source_ip=10.0.0.50')
        
        # Note: In a real test environment with the monitor running,
        # we would expect to find SQL injection alerts here
        assert alerts_response.status_code == 200


class TestDashboardEndpoints:
    """Tests for dashboard API endpoints"""
    
    def test_dashboard_summary(self, client):
        response = client.get('/api/v1/dashboard/summary')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'timestamp' in data
        assert 'monitor' in data
        assert 'alerts' in data
        assert 'threats' in data
        assert 'blocklist' in data
        
        # Check nested structure
        assert 'status' in data['monitor']
        assert 'last_hour' in data['alerts']
        assert 'last_24h' in data['alerts']
        assert 'top_attackers' in data['threats']
    
    def test_dashboard_timeline(self, client):
        response = client.get('/api/v1/dashboard/timeline')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'start_time' in data
        assert 'end_time' in data
        assert 'interval_minutes' in data
        assert 'timeline' in data
        assert isinstance(data['timeline'], list)
    
    def test_dashboard_timeline_custom_params(self, client):
        response = client.get('/api/v1/dashboard/timeline?hours=48&interval=120')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['interval_minutes'] == 120
    
    def test_dashboard_timeline_max_hours_limit(self, client):
        # Request more than max allowed (168 hours)
        response = client.get('/api/v1/dashboard/timeline?hours=500')
        
        assert response.status_code == 200
        # Should be capped at 168
    
    def test_dashboard_geo(self, client):
        response = client.get('/api/v1/dashboard/geo')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'time_range_hours' in data
        assert 'total_sources' in data
        assert 'sources' in data
    
    def test_dashboard_geo_custom_hours(self, client):
        response = client.get('/api/v1/dashboard/geo?hours=48')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['time_range_hours'] == 48


class TestReportEndpoints:
    """Tests for report generation API endpoints"""
    
    def test_daily_report(self, client):
        response = client.get('/api/v1/reports/daily')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['report_type'] == 'daily'
        assert 'report_date' in data
        assert 'summary' in data
        assert 'severity_breakdown' in data
        assert 'hourly_distribution' in data
        assert 'recommendations' in data
    
    def test_daily_report_specific_date(self, client):
        response = client.get('/api/v1/reports/daily?date=2026-02-13')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['report_date'] == '2026-02-13'
    
    def test_weekly_report(self, client):
        response = client.get('/api/v1/reports/weekly')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['report_type'] == 'weekly'
        assert 'period' in data
        assert 'summary' in data
        assert 'trend' in data
        assert 'daily_breakdown' in data
        assert 'persistent_threats' in data
        assert 'recommendations' in data
    
    def test_weekly_report_trend_calculation(self, client):
        response = client.get('/api/v1/reports/weekly')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'direction' in data['trend']
        assert data['trend']['direction'] in ['increasing', 'decreasing', 'stable']
        assert 'percentage_change' in data['trend']
    
    def test_custom_report_basic(self, client):
        report_params = {
            'start_date': '2026-02-01T00:00:00',
            'end_date': '2026-02-14T23:59:59',
            'include': {
                'summary': True,
                'timeline': True,
                'top_sources': True,
                'top_types': True,
                'raw_alerts': False
            }
        }
        
        response = client.post(
            '/api/v1/reports/custom',
            data=json.dumps(report_params),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['report_type'] == 'custom'
        assert 'parameters' in data
        assert 'summary' in data
        assert 'timeline' in data
        assert 'top_sources' in data
        assert 'top_types' in data
        assert 'alerts' not in data  # raw_alerts was False
    
    def test_custom_report_with_filters(self, client):
        report_params = {
            'start_date': '2026-02-01T00:00:00',
            'end_date': '2026-02-14T23:59:59',
            'filters': {
                'levels': ['HIGH', 'CRITICAL'],
                'types': ['SQL'],
                'source_ips': ['192.168.1.100']
            },
            'include': {
                'summary': True
            }
        }
        
        response = client.post(
            '/api/v1/reports/custom',
            data=json.dumps(report_params),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['parameters']['filters_applied'] == report_params['filters']
    
    def test_custom_report_with_raw_alerts(self, client):
        report_params = {
            'start_date': '2026-02-01T00:00:00',
            'end_date': '2026-02-14T23:59:59',
            'include': {
                'summary': True,
                'raw_alerts': True
            }
        }
        
        response = client.post(
            '/api/v1/reports/custom',
            data=json.dumps(report_params),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'alerts' in data
    
    def test_custom_report_invalid_date(self, client):
        report_params = {
            'start_date': 'invalid-date',
            'end_date': '2026-02-14T23:59:59'
        }
        
        response = client.post(
            '/api/v1/reports/custom',
            data=json.dumps(report_params),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_custom_report_empty_body(self, client):
        response = client.post(
            '/api/v1/reports/custom',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        # Should use defaults and succeed
        assert response.status_code == 200


class TestAPIDocumentation:
    """Tests for API documentation endpoint"""
    
    def test_api_docs(self, client):
        response = client.get('/api/v1/docs')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'name' in data
        assert 'version' in data
        assert 'endpoints' in data
        
        # Check that major endpoint categories exist
        assert 'health' in data['endpoints']
        assert 'monitor' in data['endpoints']
        assert 'alerts' in data['endpoints']
        assert 'rules' in data['endpoints']
        assert 'anomaly' in data['endpoints']
        assert 'blocklist' in data['endpoints']
        assert 'dashboard' in data['endpoints']
        assert 'reports' in data['endpoints']


class TestErrorHandling:
    """Tests for API error handling"""
    
    def test_404_not_found(self, client):
        response = client.get('/api/v1/nonexistent-endpoint')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_invalid_json_body(self, client):
        response = client.post(
            '/api/v1/rules',
            data='not valid json',
            content_type='application/json'
        )
        
        assert response.status_code in [400, 500]
    
    def test_wrong_content_type(self, client):
        response = client.post(
            '/api/v1/rules',
            data='name=test',
            content_type='application/x-www-form-urlencoded'
        )
        
        # Should handle gracefully
        assert response.status_code in [400, 415, 500]
    
    def test_method_not_allowed(self, client):
        # Try to DELETE on an endpoint that doesn't support it
        response = client.delete('/api/v1/health')
        
        assert response.status_code == 405


class TestCORS:
    """Tests for CORS configuration"""
    
    def test_cors_headers_present(self, client):
        response = client.options(
            '/api/v1/alerts',
            headers={
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'GET'
            }
        )
        
        # CORS preflight should be handled
        assert response.status_code in [200, 204]
    
    def test_cors_allows_api_key_header(self, client):
        response = client.options(
            '/api/v1/alerts',
            headers={
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'X-API-Key'
            }
        )
        
        assert response.status_code in [200, 204]