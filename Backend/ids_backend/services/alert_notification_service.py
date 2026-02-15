"""
Alert Notification Service - Pipeline integration point.
Called from the packet processing pipeline when alerts are produced.
Delegates to SNS notifier for AWS delivery.
"""
from services.sns_notifier import notify_alerts

__all__ = ["notify_alerts"]
