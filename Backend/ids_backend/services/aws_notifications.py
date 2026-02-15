"""
AWS SNS (SMS) and SES (Email) notification helpers.
Used by notification API routes and by alert notification handlers.
"""
import os
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


def normalize_phone_for_sns(phone: str) -> str:
    """Normalize phone to E.164 for SNS."""
    digits = ''.join(c for c in phone if c.isdigit())
    if not digits:
        return phone
    if len(digits) == 10 and not phone.strip().startswith('+'):
        return f"+1{digits}"
    return f"+{digits}"


def send_ses_email(to_addresses: List[str], subject: str, body_text: str) -> Tuple[bool, str]:
    """Send email via AWS SES. Returns (success, message)."""
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return False, "boto3 required for email. pip install boto3"
    from_email = os.environ.get('SES_FROM_EMAIL')
    if not from_email:
        return False, "SES_FROM_EMAIL not set. Configure verified sender in AWS SES."
    region = os.environ.get('AWS_REGION', 'us-east-1')
    try:
        ses = boto3.client('ses', region_name=region)
        ses.send_email(
            Source=from_email,
            Destination={'ToAddresses': to_addresses},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Text': {'Data': body_text, 'Charset': 'UTF-8'}},
            },
        )
        return True, f"Email sent to {len(to_addresses)} recipient(s)"
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        msg = str(e)
        if code == 'MessageRejected':
            return False, "SES sandbox: verify recipient emails in AWS Console, or move out of sandbox."
        return False, f"AWS SES error: {msg}"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


def send_sns_sms(phone_numbers: List[str], message: str) -> Tuple[bool, str]:
    """Send SMS via AWS SNS. Returns (success, message)."""
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return False, "boto3 required for SMS. pip install boto3"
    region = os.environ.get('AWS_REGION', 'us-east-1')
    try:
        sns = boto3.client('sns', region_name=region)
        for phone in phone_numbers:
            sns.publish(PhoneNumber=phone, Message=message)
        return True, f"SMS sent to {len(phone_numbers)} recipient(s)"
    except ClientError as e:
        return False, f"AWS SNS error: {str(e)}"
    except Exception as e:
        return False, f"Failed to send SMS: {str(e)}"


def send_alert_notification(alert, emails: List[str], phones: List[str]) -> None:
    """
    Send an alert to the given emails and phones via AWS SES/SNS.
    Logs errors but does not raise. Call when alert is HIGH or CRITICAL.
    """
    subject = f"[IDS] {alert.level.name}: {alert.alert_type}"
    body = (
        f"IDS Alert\n"
        f"Type: {alert.alert_type}\n"
        f"Level: {alert.level.name}\n"
        f"Source: {alert.source_ip}\n"
        f"Destination: {alert.destination_ip}:{alert.destination_port}\n"
        f"Description: {alert.description}"
    )
    sms_message = f"[IDS] {alert.alert_type} from {alert.source_ip}: {alert.description[:100]}"

    if emails and os.environ.get('SES_FROM_EMAIL'):
        ok, msg = send_ses_email(emails, subject, body)
        if not ok:
            logger.warning(f"Alert email notification failed: {msg}")
        else:
            logger.info(f"Alert email sent to {len(emails)} recipient(s)")

    if phones:
        normalized = [normalize_phone_for_sns(p) for p in phones]
        ok, msg = send_sns_sms(normalized, sms_message)
        if not ok:
            logger.warning(f"Alert SMS notification failed: {msg}")
        else:
            logger.info(f"Alert SMS sent to {len(phones)} recipient(s)")
