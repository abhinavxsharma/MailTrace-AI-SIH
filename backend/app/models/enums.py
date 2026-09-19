"""Enumerations and constants for MAILTRACE AI data models."""

from enum import Enum


class CaseStatus(str, Enum):
    """Lifecycle status of an email investigation case."""

    NEW = "NEW"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Classification(str, Enum):
    """Threat classification assigned to an email case."""

    PENDING = "PENDING"
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"


class MailboxStatus(str, Enum):
    """Operational status of a connected mailbox."""

    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"
