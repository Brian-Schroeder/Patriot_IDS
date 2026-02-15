"""
AWS SNS Alert Notification Service
Sends classified Alert objects via SNS Topic. Email subscribers are configured in AWS.
"""
import json
import os
import logging
from typing import List

from models.alert import Alert

logger = logging.getLogger(__name__)

# Topic ARN - configurable via SNS_TOPIC_ARN env
DEFAULT_TOPIC_ARN = "arn:aws:sns:us-east-1:988718950747:nids-alerts"
TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", DEFAULT_TOPIC_ARN)
REGION = os.environ.get("AWS_REGION", "us-east-1")


def notify_alerts(alerts: List[Alert]) -> None:
    """Publish one or more Alert objects to AWS SNS Topic."""
    if not TOPIC_ARN or "PASTE_YOUR" in TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured; skipping notification")
        return

    try:
        import boto3
    except ImportError:
        logger.warning("boto3 required for SNS. pip install boto3")
        return

    sns = boto3.client("sns", region_name=REGION)

    for alert in alerts:
        try:
            message = f"""
Alert Type: {alert.alert_type}
Severity: {alert.level.name}
Source IP: {alert.source_ip}
Destination IP: {alert.destination_ip}
Port: {alert.destination_port}
Time: {alert.timestamp}

Description:
{alert.description}

Metadata:
{json.dumps(alert.metadata, default=str)}
"""
            sns.publish(
                TopicArn=TOPIC_ARN,
                Subject=f"NIDS Alert - {alert.level.name}",
                Message=message.strip(),
            )
            logger.info(f"Alert sent via SNS: {alert.alert_type}")
        except Exception as e:
            logger.error(f"Failed to send SNS alert: {e}")


def send_test_notification() -> tuple[bool, str]:
    """
    Send a test alert to the SNS topic. Returns (success, message).
    """
    if not TOPIC_ARN or "PASTE_YOUR" in TOPIC_ARN:
        return False, "SNS_TOPIC_ARN not configured. Set SNS_TOPIC_ARN env var."

    try:
        import boto3
    except ImportError:
        return False, "boto3 required. pip install boto3"

    try:
        sns = boto3.client("sns", region_name=REGION)
        message = """
Alert Type: Test Notification
Severity: LOW
Source IP: 127.0.0.1
Destination IP: -
Port: -
Time: (now)

Description:
This is a test notification from the IDS control panel. Alert notifications are working.

Metadata:
{}
"""
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="NIDS Alert - Test",
            Message=message.strip(),
        )
        return True, "Test notification sent to SNS topic"
    except Exception as e:
        return False, str(e)
