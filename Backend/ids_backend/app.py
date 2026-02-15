import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from api.routes import api, init_routes
from services.alert_service import AlertService, WebhookNotifier, EmailNotifier
from services.sns_notifier import SNSNotifier
from services.traffic_monitor import TrafficMonitor
from models.alert import AlertLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ids.log')
    ]
)
logger = logging.getLogger(__name__)


def create_app(config_class=Config) -> Flask:
    """Application factory"""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Enable CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": os.environ.get('CORS_ORIGINS', '*').split(','),
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "allow_headers": ["Content-Type", "X-API-Key"]
        }
    })
    
    # Initialize services
    alert_service = AlertService(
        log_file=app.config.get('LOG_FILE', 'ids_alerts.log'),
        max_alerts=10000
    )
    
    traffic_monitor = TrafficMonitor(
        alert_service=alert_service,
        interface=app.config.get('NETWORK_INTERFACE', 'eth0'),
        use_anomaly_detection=True,
        use_signature_detection=True
    )
    
    # Configure notification handlers (optional)
    _configure_notifications(app, alert_service)
    
    # Initialize API routes with services
    init_routes(alert_service, traffic_monitor)
    
    # Register blueprints
    app.register_blueprint(api)
    
    # Register root routes
    @app.route('/')
    def index():
        return jsonify({
            'name': 'Intrusion Detection System API',
            'version': '1.0.0',
            'status': 'operational',
            'documentation': '/api/v1/docs',
            'health_check': '/api/v1/health'
        })
    
    @app.route('/api/v1/docs')
    def api_docs():
        """Return API documentation"""
        return jsonify({
            'name': 'IDS API Documentation',
            'version': '1.0.0',
            'base_url': '/api/v1',
            'endpoints': {
                'health': {
                    'GET /health': 'Health check endpoint',
                    'GET /status': 'System status overview',
                    'GET /stats': 'Detailed statistics'
                },
                'pipeline': {
                    'POST /pipeline/run-anomaly': 'Run anomaly pipeline (DB1 -> detector -> DB2)',
                },
                'monitor': {
                    'POST /monitor/start': 'Start traffic monitoring',
                    'POST /monitor/stop': 'Stop traffic monitoring',
                    'GET /monitor/status': 'Get monitor status',
                    'POST /monitor/inject': 'Inject packet for testing'
                },
                'alerts': {
                    'GET /alerts': 'List alerts with filtering',
                    'GET /alerts/<id>': 'Get specific alert',
                    'PUT /alerts/<id>/status': 'Update alert status',
                    'PUT /alerts/bulk/status': 'Bulk update alert status',
                    'DELETE /alerts/<id>': 'Delete alert',
                    'GET /alerts/export': 'Export alerts (JSON/CSV)',
                    'GET /alerts/statistics': 'Alert statistics'
                },
                'rules': {
                    'GET /rules': 'List detection rules',
                    'GET /rules/<id>': 'Get specific rule',
                    'POST /rules': 'Create new rule',
                    'PUT /rules/<id>': 'Update rule',
                    'DELETE /rules/<id>': 'Delete rule',
                    'POST /rules/<id>/toggle': 'Enable/disable rule',
                    'POST /rules/test': 'Test rule pattern'
                },
                'anomaly': {
                    'GET /anomaly/thresholds': 'Get detection thresholds',
                    'PUT /anomaly/thresholds': 'Update thresholds',
                    'GET /anomaly/statistics': 'Get anomaly statistics',
                    'POST /anomaly/baseline/reset': 'Reset baseline',
                    'POST /anomaly/failed-auth': 'Record failed auth'
                },
                'notifications': {
                    'POST /notifications/test': 'Send test alert to SNS topic',
                },
                'blocklist': {
                    'GET /blocklist': 'List blocked IPs',
                    'POST /blocklist': 'Add IP to blocklist',
                    'DELETE /blocklist/<ip>': 'Remove IP from blocklist',
                    'GET /blocklist/check/<ip>': 'Check if IP is blocked'
                },
                'dashboard': {
                    'GET /dashboard/summary': 'Dashboard summary data',
                    'GET /dashboard/timeline': 'Alert timeline data',
                    'GET /dashboard/geo': 'Geographic distribution'
                },
                'reports': {
                    'GET /reports/daily': 'Daily security report',
                    'GET /reports/weekly': 'Weekly security report',
                    'POST /reports/custom': 'Generate custom report'
                }
            }
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    # Shutdown handler
    @app.teardown_appcontext
    def shutdown_services(exception=None):
        if traffic_monitor and traffic_monitor.stats.is_running:
            logger.info("Shutting down traffic monitor...")
            traffic_monitor.stop()
    
    logger.info("IDS Application initialized successfully")
    return app


def _configure_notifications(app: Flask, alert_service: AlertService) -> None:
    """Configure alert notification handlers based on environment"""
    
    # Webhook notifications
    webhook_url = os.environ.get('WEBHOOK_URL')
    if webhook_url:
        webhook_notifier = WebhookNotifier(
            webhook_url=webhook_url,
            min_level=AlertLevel.MEDIUM,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {os.environ.get('WEBHOOK_TOKEN', '')}"
            }
        )
        alert_service.register_notification_handler(webhook_notifier)
        logger.info(f"Webhook notifications enabled: {webhook_url}")
    
    # Email notifications
    smtp_host = os.environ.get('SMTP_HOST')
    if smtp_host:
        try:
            email_notifier = EmailNotifier(
                smtp_host=smtp_host,
                smtp_port=int(os.environ.get('SMTP_PORT', 587)),
                username=os.environ.get('SMTP_USERNAME', ''),
                password=os.environ.get('SMTP_PASSWORD', ''),
                from_address=os.environ.get('SMTP_FROM', 'ids@example.com'),
                to_addresses=os.environ.get('ALERT_EMAILS', '').split(','),
                min_level=AlertLevel.HIGH
            )
            alert_service.register_notification_handler(email_notifier)
            logger.info("Email notifications enabled")
        except Exception as e:
            logger.warning(f"Failed to configure email notifications: {e}")
    
    # Slack notifications (example custom handler)
    slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
    if slack_webhook:
        def slack_notifier(alert):
            if alert.level.value < AlertLevel.HIGH.value:
                return
            
            import requests
            
            color = {
                AlertLevel.HIGH: '#ff9800',
                AlertLevel.CRITICAL: '#f44336'
            }.get(alert.level, '#2196f3')
            
            payload = {
                'attachments': [{
                    'color': color,
                    'title': f"🚨 IDS Alert: {alert.alert_type}",
                    'fields': [
                        {'title': 'Level', 'value': alert.level.name, 'short': True},
                        {'title': 'Source IP', 'value': alert.source_ip, 'short': True},
                        {'title': 'Description', 'value': alert.description, 'short': False}
                    ],
                    'footer': f"Alert ID: {alert.id}",
                    'ts': int(alert.timestamp.timestamp())
                }]
            }
            
            try:
                requests.post(slack_webhook, json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Slack notification failed: {e}")
        
        alert_service.register_notification_handler(slack_notifier)
        logger.info("Slack notifications enabled")

    # Database persistence - persist alerts to MongoDB via IDS Database service
    database_url = os.environ.get("IDS_DATABASE_URL", "")
    if database_url:
        from services.database_client import persist_alert

        def db_persist_handler(alert):
            persist_alert(alert)

        alert_service.register_notification_handler(db_persist_handler)
        logger.info(f"Database persistence enabled: {database_url}")

    # SNS notifications are invoked from the pipeline layer (traffic_monitor._process_packets)
    # not from alert_service handlers, per AWS architecture guidance

    # SNS notifications (AWS)
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if sns_topic_arn:
        try:
            sns_notifier = SNSNotifier(min_level=AlertLevel.HIGH)
            alert_service.register_notification_handler(sns_notifier)
            logger.info("SNS notifications enabled")
        except Exception as e:
            logger.warning(f"Failed to configure SNS notifications: {e}")


# Application instance
app = create_app()


if __name__ == '__main__':
    # Get configuration from environment
    host = os.environ.get('IDS_HOST', '0.0.0.0')
    port = int(os.environ.get('IDS_PORT', 5000))
    debug = os.environ.get('IDS_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting IDS API server on {host}:{port}")
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )