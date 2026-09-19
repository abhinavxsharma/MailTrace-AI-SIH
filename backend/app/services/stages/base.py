"""Base interface definition for analysis pipeline stages."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from backend.app.schemas.analysis import NormalizedEmail


class BaseAnalysisStage(ABC):
    """Abstract base class for all modular analysis pipeline stages.

    Future specialized modules (forensics, ML, intelligence, etc.) should
    inherit from this interface and implement the `analyze` method.
    """

    stage_name: str = "base"

    @abstractmethod
    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis stage against a normalized email and execution context.

        Args:
            email: Standardized normalized email metadata and content.
            context: Shared pipeline context dictionary (e.g. case_id, prior stage outputs).

        Returns:
            Structured dictionary of stage findings.
        """
        raise NotImplementedError
