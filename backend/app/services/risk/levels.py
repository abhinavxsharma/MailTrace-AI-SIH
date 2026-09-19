"""Risk levels and threshold mappings for MAILTRACE AI."""

from enum import Enum


class RiskLevel(str, Enum):
    """Categorical threat severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def get_risk_level(score: int) -> str:
    """Map a deterministic risk score (0-100) to its corresponding risk level.

    Thresholds:
        0 - 39:   LOW
        40 - 69:  MEDIUM
        70 - 84:  HIGH
        85 - 100: CRITICAL

    Args:
        score: Computed integer risk score.

    Returns:
        Risk level string ("LOW", "MEDIUM", "HIGH", "CRITICAL").

    Raises:
        ValueError: If the score is outside the valid range [0, 100] or not an integer.
    """
    if not isinstance(score, int) or isinstance(score, bool):
        raise ValueError(f"Score must be an integer, received: {type(score).__name__}")

    if not (0 <= score <= 100):
        raise ValueError(f"Score must be between 0 and 100 inclusive, received: {score}")

    if score <= 39:
        return RiskLevel.LOW.value
    elif score <= 69:
        return RiskLevel.MEDIUM.value
    elif score <= 84:
        return RiskLevel.HIGH.value
    else:
        return RiskLevel.CRITICAL.value
