"""Enumerations and constants for MAILTRACE AI data models."""

from enum import Enum


class CaseStatus(str, Enum):
    """Lifecycle status of an email investigation case."""

    NEW = "NEW"
    PROCESSING = "PROCESSING"
    ANALYZED = "ANALYZED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Classification(str, Enum):
    """Threat classification assigned to an email case."""

    PENDING = "PENDING"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class MailboxStatus(str, Enum):
    """Operational status of a connected mailbox."""

    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"


class AlertStatus(str, Enum):
    """Lifecycle status of a mailbox threat alert."""

    UNREAD = "UNREAD"
    READ = "READ"
    DISMISSED = "DISMISSED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
