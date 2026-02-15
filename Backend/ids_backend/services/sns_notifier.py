"""
AWS SNS Alert Notification Service
Implements a notification handler compatible with AlertService.
Sends alerts to AWS SNS Topic (email subscribers configured in AWS).
"""

import os
import json
import logging
from typing import Optional
import boto3

from models.alert import Alert, AlertLevel

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

DEFAULT_TOPIC_ARN = "arn:aws:sns:us-east-1:988718950747:nids-alerts"
TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", DEFAULT_TOPIC_ARN)
REGION = os.environ.get("AWS_REGION", "us-east-1")


# -----------------------------------------------------------------------------
# SNS Notification Handler (for AlertService)
# -----------------------------------------------------------------------------

class SNSNotifier:
    """
    Notification handler for AlertService.
    Automatically publishes alerts to AWS SNS when triggered.
    """

    def __init__(self, min_level: AlertLevel = AlertLevel.HIGH):
        self.min_level = min_level
        self.sns = boto3.client("sns", region_name=REGION)

    def __call__(self, alert: Alert) -> None:
        """
        Called automatically by AlertService when an alert is added.
        """

        # Filter by severity
        if alert.level.value < self.min_level.value:
            return

        if not TOPIC_ARN:
            logger.warning("SNS_TOPIC_ARN not configured; skipping notification")
            return

        try:
            message = f"""
Intrusion Detection Alert

Level: {alert.level.name}
Type: {alert.alert_type}
Time: {alert.timestamp}

Source IP: {alert.source_ip}
Destination IP: {alert.destination_ip}
Destination Port: {alert.destination_port}

Description:
{alert.description}

Alert ID: {alert.id}

Metadata:
{json.dumps(alert.metadata, default=str)}
""".strip()

            self.sns.publish(
                TopicArn=TOPIC_ARN,
                Subject=f"[IDS {alert.level.name}] {alert.alert_type}",
                Message=message
            )

            logger.info(f"SNS notification sent for alert {alert.id}")

        except Exception as e:
            logger.error(f"SNS notification failed: {e}")


# -----------------------------------------------------------------------------
# Manual Test Function (used by /notifications/test endpoint)
# -----------------------------------------------------------------------------

def send_test_notification() -> tuple[bool, str]:
    """
    Send a test alert to the SNS topic.
    Returns (success, message).
    """

    if not TOPIC_ARN:
        return False, "SNS_TOPIC_ARN not configured."

    try:
        sns = boto3.client("sns", region_name=REGION)

        message = """
Intrusion Detection System Test Notification

Severity: LOW
Source IP: 127.0.0.1
Destination: -
Time: (now)

This is a test notification from the IDS Control Panel.
SNS notifications are working correctly.
""".strip()

        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="[IDS] Test Notification",
            Message=message
        )

        return True, "Test notification sent successfully."

    except Exception as e:
        logger.exception("Test notification failed")
        return False, str(e)
