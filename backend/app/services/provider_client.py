"""Abstract mail provider client defining connector handoff contract."""

from abc import ABC, abstractmethod
from typing import Optional
from backend.app.schemas.analysis import NormalizedEmail


class MailProviderClient(ABC):
    """Abstract interface defining the contract for mailbox provider connectors.

    Tanvi's future provider-specific connector (e.g. GmailProviderClient,
    OutlookProviderClient) will implement this interface to fetch raw messages
    via provider APIs and convert them into NormalizedEmail objects for the
    AnalysisPipeline.
    """

    @abstractmethod
    def fetch_message(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> NormalizedEmail:
        """Fetch message content from mailbox provider and return normalized email.

        Args:
            provider_message_id: Unique message ID from provider.
            account_email: Associated connected account email.

        Returns:
            NormalizedEmail ready for AnalysisPipeline ingestion.

        Raises:
            NotImplementedError: In base class.
        """
        raise NotImplementedError
