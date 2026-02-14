import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from services.alert_service import AlertService
from models.alert import Alert, AlertLevel, AlertStatus


class TestAlertService:
    """Tests for AlertService"""
    
    def setup_method(self):
        self.service = AlertService(log_file='/tmp/test_ids_alerts.log', max_alerts=100)
    
    def _create_alert(self, level=AlertLevel.MEDIUM, source_ip='192.168.1.100'):
        return Alert(
            alert_type='TEST_ALERT',
            source_ip=source_ip,
            description='Test alert description',
            level=level,
            destination_ip='10.0.0.1',
            destination_port=80
        )
    
    def test_add_alert(self):
        alert = self._create_alert()
        alert_id = self.service.add_alert(alert)
        
        assert alert_id is not None
        assert self.service.get_alert(alert_id) is not None
    
    def test_get_alert(self):
        alert = self._create_alert()
        alert_id = self.service.add_alert(alert)
        
        retrieved = self.service.get_alert(alert_id)
        
        assert retrieved is not None
        assert retrieved.alert_type == 'TEST_ALERT'
        assert retrieved.source_ip == '192.168.1.100'
    
    def test_get_nonexistent_alert(self):
        result = self.service.get_alert('nonexistent-id')
        assert result is None
    
    def test_get_alerts_no_filter(self):
        # Add multiple alerts
        for i in range(5):
            self.service.add_alert(self._create_alert(source_ip=f'192.168.1.{i}'))
        
        alerts = self.service.get_alerts()
        assert len(alerts) == 5
    
    def test_get_alerts_filter_by_level(self):
        self.service.add_alert(self._create_alert(level=AlertLevel.LOW))
        self.service.add_alert(self._create_alert(level=AlertLevel.MEDIUM))
        self.service.add_alert(self._create_alert(level=AlertLevel.HIGH))
        self.service.add_alert(self._create_alert(level=AlertLevel.CRITICAL))
        
        high_alerts = self.service.get_alerts(level=AlertLevel.HIGH)
        assert len(high_alerts) == 1
        assert high_alerts[0].level == AlertLevel.HIGH
    
    def test_get_alerts_filter_by_source_ip(self):
        self.service.add_alert(self._create_alert(source_ip='192.168.1.1'))
        self.service.add_alert(self._create_alert(source_ip='192.168.1.2'))
        self.service.add_alert(self._create_alert(source_ip='192.168.1.1'))
        
        filtered = self.service.get_alerts(source_ip='192.168.1.1')
        assert len(filtered) == 2
    
    def test_get_alerts_filter_by_status(self):
        alert1 = self._create_alert()
        alert2 = self._create_alert()
        
        self.service.add_alert(alert1)
        alert2_id = self.service.add_alert(alert2)
        
        self.service.update_alert_status(alert2_id, AlertStatus.ACKNOWLEDGED)
        
        new_alerts = self.service.get_alerts(status=AlertStatus.NEW)
        ack_alerts = self.service.get_alerts(status=AlertStatus.ACKNOWLEDGED)
        
        assert len(new_alerts) == 1
        assert len(ack_alerts) == 1
    
    def test_get_alerts_pagination(self):
        for i in range(20):
            self.service.add_alert(self._create_alert())
        
        page1 = self.service.get_alerts(limit=10, offset=0)
        page2 = self.service.get_alerts(limit=10, offset=10)
        
        assert len(page1) == 10
        assert len(page2) == 10
        assert page1[0].id != page2[0].id
    
    def test_update_alert_status(self):
        alert = self._create_alert()
        alert_id = self.service.add_alert(alert)
        
        success = self.service.update_alert_status(
            alert_id,
            AlertStatus.RESOLVED,
            notes='Issue resolved'
        )
        
        assert success is True
        
        updated = self.service.get_alert(alert_id)
        assert updated.status == AlertStatus.RESOLVED
        assert updated.metadata.get('status_notes') == 'Issue resolved'
    
    def test_update_nonexistent_alert_status(self):
        success = self.service.update_alert_status('fake-id', AlertStatus.RESOLVED)
        assert success is False
    
    def test_bulk_update_status(self):
        ids = []
        for i in range(5):
            alert = self._create_alert()
            ids.append(self.service.add_alert(alert))
        
        results = self.service.bulk_update_status(ids[:3], AlertStatus.ACKNOWLEDGED)
        
        assert all(results.values())
        
        for alert_id in ids[:3]:
            assert self.service.get_alert(alert_id).status == AlertStatus.ACKNOWLEDGED
    
    def test_delete_alert(self):
        alert = self._create_alert()
        alert_id = self.service.add_alert(alert)
        
        assert self.service.get_alert(alert_id) is not None
        
        success = self.service.delete_alert(alert_id)
        assert success is True
        assert self.service.get_alert(alert_id) is None
    
    def test_delete_nonexistent_alert(self):
        success = self.service.delete_alert('fake-id')
        assert success is False
    
    def test_max_alerts_cleanup(self):
        # Set low max for testing
        self.service.max_alerts = 10
        
        # Add more than max
        for i in range(15):
            self.service.add_alert(self._create_alert(source_ip=f'192.168.1.{i}'))
        
        # Should only have max_alerts
        assert len(self.service.alerts) <= 10
    
    def test_rate_limiting(self):
        # Same alert type and source should be rate limited
        alert1 = Alert(
            alert_type='RATE_TEST',
            source_ip='192.168.1.100',
            description='Test',
            level=AlertLevel.MEDIUM,
            destination_port=80
        )
        alert2 = Alert(
            alert_type='RATE_TEST',
            source_ip='192.168.1.100',
            description='Test duplicate',
            level=AlertLevel.MEDIUM,
            destination_port=80
        )
        
        id1 = self.service.add_alert(alert1)
        id2 = self.service.add_alert(alert2)  # Should be rate limited
        
        assert id1 is not None
        assert id2 is None  # Rate limited
    
    def test_rate_limiting_bypass(self):
        alert1 = Alert(
            alert_type='BYPASS_TEST',
            source_ip='192.168.1.100',
            description='Test',
            level=AlertLevel.MEDIUM,
            destination_port=80
        )
        alert2 = Alert(
            alert_type='BYPASS_TEST',
            source_ip='192.168.1.100',
            description='Test duplicate',
            level=AlertLevel.MEDIUM,
            destination_port=80
        )
        
        id1 = self.service.add_alert(alert1)
        id2 = self.service.add_alert(alert2, bypass_rate_limit=True)  # Bypass rate limit
        
        assert id1 is not None
        assert id2 is not None  # Should succeed with bypass
    
    def test_get_statistics(self):
        # Add various alerts
        self.service.add_alert(self._create_alert(level=AlertLevel.LOW, source_ip='192.168.1.1'))
        self.service.add_alert(self._create_alert(level=AlertLevel.MEDIUM, source_ip='192.168.1.2'))
        self.service.add_alert(self._create_alert(level=AlertLevel.HIGH, source_ip='192.168.1.1'))
        self.service.add_alert(self._create_alert(level=AlertLevel.CRITICAL, source_ip='192.168.1.3'))
        
        stats = self.service.get_statistics()
        
        assert stats['total_alerts'] == 4
        assert stats['by_level']['LOW'] == 1
        assert stats['by_level']['MEDIUM'] == 1
        assert stats['by_level']['HIGH'] == 1
        assert stats['by_level']['CRITICAL'] == 1
        assert '192.168.1.1' in stats['top_sources']
    
    def test_export_alerts_json(self):
        self.service.add_alert(self._create_alert())
        self.service.add_alert(self._create_alert())
        
        export = self.service.export_alerts(format='json')
        
        import json
        data = json.loads(export)
        
        assert isinstance(data, list)
        assert len(data) == 2
        assert 'alert_type' in data[0]
    
    def test_export_alerts_csv(self):
        self.service.add_alert(self._create_alert())
        self.service.add_alert(self._create_alert())
        
        export = self.service.export_alerts(format='csv')
        
        lines = export.strip().split('\n')
        assert len(lines) == 3  # Header + 2 alerts
        assert 'id,timestamp,level' in lines[0]
    
    def test_export_alerts_invalid_format(self):
        with pytest.raises(ValueError):
            self.service.export_alerts(format='xml')
    
    def test_export_alerts_with_since_filter(self):
        # Add old alert (simulate by adding then filtering)
        self.service.add_alert(self._create_alert())
        
        # Export with future timestamp should return empty
        future = datetime.utcnow() + timedelta(hours=1)
        export = self.service.export_alerts(format='json', since=future)
        
        import json
        data = json.loads(export)
        assert len(data) == 0
    
    def test_notification_handler_called(self):
        mock_handler = Mock()
        self.service.register_notification_handler(mock_handler)
        
        alert = self._create_alert()
        self.service.add_alert(alert)
        
        mock_handler.assert_called_once()
        called_alert = mock_handler.call_args[0][0]
        assert called_alert.alert_type == 'TEST_ALERT'
    
    def test_multiple_notification_handlers(self):
        handler1 = Mock()
        handler2 = Mock()
        
        self.service.register_notification_handler(handler1)
        self.service.register_notification_handler(handler2)
        
        self.service.add_alert(self._create_alert())
        
        handler1.assert_called_once()
        handler2.assert_called_once()
    
    def test_notification_handler_exception_handled(self):
        """Notification handler exception should not prevent alert creation"""
        def failing_handler(alert):
            raise Exception("Handler failed")
        
        self.service.register_notification_handler(failing_handler)
        
        alert = self._create_alert()
        alert_id = self.service.add_alert(alert)
        
        # Alert should still be created despite handler failure
        assert alert_id is not None
        assert self.service.get_alert(alert_id) is not None


class TestAlertModel:
    """Tests for Alert model"""
    
    def test_alert_creation(self):
        alert = Alert(
            alert_type='TEST',
            source_ip='192.168.1.1',
            description='Test description',
            level=AlertLevel.HIGH
        )
        
        assert alert.id is not None
        assert alert.timestamp is not None
        assert alert.status == AlertStatus.NEW
    
    def test_alert_to_dict(self):
        alert = Alert(
            alert_type='TEST',
            source_ip='192.168.1.1',
            description='Test description',
            level=AlertLevel.HIGH,
            destination_ip='10.0.0.1',
            destination_port=443,
            metadata={'key': 'value'}
        )
        
        alert_dict = alert.to_dict()
        
        assert alert_dict['alert_type'] == 'TEST'
        assert alert_dict['source_ip'] == '192.168.1.1'
        assert alert_dict['level'] == 'HIGH'
        assert alert_dict['status'] == 'new'
        assert alert_dict['metadata']['key'] == 'value'
    
    def test_alert_level_comparison(self):
        assert AlertLevel.CRITICAL.value > AlertLevel.HIGH.value
        assert AlertLevel.HIGH.value > AlertLevel.MEDIUM.value
        assert AlertLevel.MEDIUM.value > AlertLevel.LOW.value


class TestWebhookNotifier:
    """Tests for WebhookNotifier"""
    
    @patch('requests.post')
    def test_webhook_called_for_high_alert(self, mock_post):
        from services.alert_service import WebhookNotifier
        
        mock_post.return_value.status_code = 200
        
        notifier = WebhookNotifier(
            webhook_url='https://example.com/webhook',
            min_level=AlertLevel.MEDIUM
        )
        
        alert = Alert(
            alert_type='TEST',
            source_ip='192.168.1.1',
            description='Test',
            level=AlertLevel.HIGH
        )
        
        notifier(alert)
        
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert 'https://example.com/webhook' in call_args[0] or call_args[1].get('url') == 'https://example.com/webhook'
    
    @patch('requests.post')
    def test_webhook_not_called_for_low_alert(self, mock_post):
        from services.alert_service import WebhookNotifier
        
        notifier = WebhookNotifier(
            webhook_url='https://example.com/webhook',
            min_level=AlertLevel.HIGH
        )
        
        alert = Alert(
            alert_type='TEST',
            source_ip='192.168.1.1',
            description='Test',
            level=AlertLevel.LOW
        )
        
        notifier(alert)
        
        mock_post.assert_not_called()
    
    @patch('requests.post')
    def test_webhook_handles_failure(self, mock_post):
        from services.alert_service import WebhookNotifier
        
        mock_post.side_effect = Exception("Connection failed")
        
        notifier = WebhookNotifier(
            webhook_url='https://example.com/webhook',
            min_level=AlertLevel.LOW
        )
        
        alert = Alert(
            alert_type='TEST',
            source_ip='192.168.1.1',
            description='Test',
            level=AlertLevel.HIGH
        )
        
        # Should not raise exception
        notifier(alert)