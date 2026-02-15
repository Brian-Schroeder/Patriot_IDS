"""
In-memory store for notification recipients (emails, phones).
Used by the Notification Center and by alert notification handlers.
"""
from threading import Lock
from typing import List

_lock = Lock()
_emails: List[str] = []
_phones: List[str] = []


def get_recipients() -> dict:
    """Return current emails and phones."""
    with _lock:
        return {"emails": list(_emails), "phones": list(_phones)}


def set_recipients(emails: List[str], phones: List[str]) -> None:
    """Replace stored recipients with validated lists."""
    global _emails, _phones
    with _lock:
        _emails = [e.strip().lower() for e in emails if isinstance(e, str) and e.strip()]
        _phones = [p.strip() for p in phones if isinstance(p, str) and p.strip()]
