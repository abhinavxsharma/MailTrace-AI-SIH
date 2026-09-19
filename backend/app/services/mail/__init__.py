"""
MAILTRACE AI — Mail connector service package.

Provides the Gmail mailbox connector:

    gmail_auth        — OAuth 2.0 credential management
    gmail_client      — Typed wrapper over the Gmail API
    gmail_watch       — Mailbox push-notification (watch) management
    message_fetcher   — In-memory message retrieval and normalisation
    models            — Typed domain models (NormalizedEmail)

PRIVACY GUARANTEE
-----------------
No raw Gmail message content (MIME, .eml, message body) is written to
disk by any module in this package.  All message processing occurs
entirely in memory.  Only selected normalised forensic metadata is
later persisted by the backend persistence layer (Chunk N).
"""
