"""
Tests for gmail_auth.py (app.services.mail.gmail_auth).

No real Google credentials, internet access, or OAuth flow required.
All external calls are mocked.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from app.services.mail.gmail_auth import (
    GmailAuthError,
    GMAIL_READONLY_SCOPE,
    GMAIL_SCOPES,
    _validate_secrets_path,
    _load_cached_token,
)


# --------------------------------------------------------------------------- #
# Helpers / fixtures                                                           #
# --------------------------------------------------------------------------- #

def _fake_settings(
    *,
    secrets_file: str = "/fake/credentials.json",
    token_file: str = "/fake/.secrets/token.json",
    project: str = "",
    topic: str = "",
) -> MagicMock:
    """Return a mock Settings object."""
    s = MagicMock()
    s.GOOGLE_OAUTH_CLIENT_SECRETS_FILE = secrets_file
    s.GOOGLE_OAUTH_TOKEN_FILE = token_file
    s.GOOGLE_CLOUD_PROJECT = project
    s.GMAIL_PUBSUB_TOPIC = topic
    s.pubsub_topic_resource = (
        f"projects/{project}/topics/{topic}" if project and topic else ""
    )
    return s


# --------------------------------------------------------------------------- #
# Scope / constant tests                                                       #
# --------------------------------------------------------------------------- #

class TestGmailScopes:

    def test_readonly_scope_value(self):
        assert GMAIL_READONLY_SCOPE == "https://www.googleapis.com/auth/gmail.readonly"

    def test_scopes_list_contains_readonly_only(self):
        """Only the read-only scope is requested — no send/modify permissions."""
        assert GMAIL_SCOPES == [GMAIL_READONLY_SCOPE]
        assert len(GMAIL_SCOPES) == 1

    def test_no_send_scope(self):
        assert not any("send" in s for s in GMAIL_SCOPES)

    def test_no_modify_scope(self):
        assert not any("modify" in s for s in GMAIL_SCOPES)

    def test_no_compose_scope(self):
        assert not any("compose" in s for s in GMAIL_SCOPES)


# --------------------------------------------------------------------------- #
# GmailAuthError tests                                                         #
# --------------------------------------------------------------------------- #

class TestGmailAuthError:

    def test_is_exception(self):
        err = GmailAuthError("test error")
        assert isinstance(err, Exception)

    def test_message_attribute(self):
        err = GmailAuthError("missing credentials", detail="GOOGLE_OAUTH_CLIENT_SECRETS_FILE")
        assert err.message == "missing credentials"
        assert err.detail == "GOOGLE_OAUTH_CLIENT_SECRETS_FILE"

    def test_detail_defaults_to_none(self):
        err = GmailAuthError("plain error")
        assert err.detail is None

    def test_repr(self):
        err = GmailAuthError("msg", detail="dtl")
        assert "GmailAuthError" in repr(err)


# --------------------------------------------------------------------------- #
# _validate_secrets_path tests                                                 #
# --------------------------------------------------------------------------- #

class TestValidateSecretsPath:

    def test_empty_path_raises_auth_error(self):
        with pytest.raises(GmailAuthError) as exc_info:
            _validate_secrets_path(Path(""))
        assert "GOOGLE_OAUTH_CLIENT_SECRETS_FILE" in str(exc_info.value)

    def test_whitespace_path_raises_auth_error(self):
        with pytest.raises(GmailAuthError):
            _validate_secrets_path(Path("   "))

    def test_nonexistent_file_raises_auth_error(self, tmp_path):
        missing = tmp_path / "does_not_exist.json"
        with pytest.raises(GmailAuthError) as exc_info:
            _validate_secrets_path(missing)
        assert "not found" in str(exc_info.value).lower() or "credentials" in str(exc_info.value).lower()

    def test_existing_file_does_not_raise(self, tmp_path):
        real_file = tmp_path / "credentials.json"
        real_file.write_text('{"installed": {}}', encoding="utf-8")
        # Should not raise
        _validate_secrets_path(real_file)


# --------------------------------------------------------------------------- #
# _load_cached_token tests                                                     #
# --------------------------------------------------------------------------- #

class TestLoadCachedToken:

    def test_missing_token_file_returns_none(self, tmp_path):
        missing = tmp_path / "token.json"
        result = _load_cached_token(missing)
        assert result is None

    def test_unparseable_token_file_returns_none(self, tmp_path):
        bad_file = tmp_path / "token.json"
        bad_file.write_text("NOT JSON", encoding="utf-8")
        result = _load_cached_token(bad_file)
        assert result is None  # Error is logged, None returned

    def test_valid_token_file_returns_credentials(self, tmp_path):
        """Mock google.oauth2.credentials.Credentials.from_authorized_user_file."""
        mock_creds = MagicMock()
        mock_creds.valid = True

        token_file = tmp_path / "token.json"
        token_file.write_text('{}', encoding="utf-8")  # content doesn't matter; library is mocked

        with patch(
            "google.oauth2.credentials.Credentials.from_authorized_user_file",
            return_value=mock_creds,
        ):
            result = _load_cached_token(token_file)

        assert result is mock_creds


# --------------------------------------------------------------------------- #
# get_credentials integration tests (mocked)                                   #
# --------------------------------------------------------------------------- #

class TestGetCredentials:

    def test_missing_secrets_file_raises_gmail_auth_error(self, tmp_path):
        """Missing credentials.json → GmailAuthError, not a crash."""
        from app.services.mail.gmail_auth import get_credentials

        settings = _fake_settings(secrets_file=str(tmp_path / "missing.json"))
        with pytest.raises(GmailAuthError):
            get_credentials(settings)

    def test_empty_secrets_path_raises_gmail_auth_error(self):
        """Empty GOOGLE_OAUTH_CLIENT_SECRETS_FILE → GmailAuthError."""
        from app.services.mail.gmail_auth import get_credentials

        settings = _fake_settings(secrets_file="")
        with pytest.raises(GmailAuthError):
            get_credentials(settings)

    def test_valid_cached_credentials_returned_without_flow(self, tmp_path):
        """If a valid cached token exists, no OAuth flow is initiated."""
        from app.services.mail.gmail_auth import get_credentials

        # Create a real-looking credentials.json file.
        secrets_file = tmp_path / "credentials.json"
        secrets_file.write_text('{"installed": {}}', encoding="utf-8")

        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.expired = False

        settings = _fake_settings(
            secrets_file=str(secrets_file),
            token_file=str(tmp_path / "token.json"),
        )

        with patch(
            "app.services.mail.gmail_auth._load_cached_token",
            return_value=mock_creds,
        ):
            result = get_credentials(settings)

        assert result is mock_creds

    def test_expired_credentials_trigger_refresh(self, tmp_path):
        """Expired token → refresh is called, not full OAuth flow."""
        from app.services.mail.gmail_auth import get_credentials

        secrets_file = tmp_path / "credentials.json"
        secrets_file.write_text('{"installed": {}}', encoding="utf-8")

        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = "fake_refresh_token"

        settings = _fake_settings(
            secrets_file=str(secrets_file),
            token_file=str(tmp_path / "token.json"),
        )

        with (
            patch("app.services.mail.gmail_auth._load_cached_token", return_value=mock_creds),
            patch("app.services.mail.gmail_auth._refresh_credentials", return_value=mock_creds) as mock_refresh,
            patch("app.services.mail.gmail_auth._save_token"),
        ):
            result = get_credentials(settings)

        mock_refresh.assert_called_once_with(mock_creds)
        assert result is mock_creds


# --------------------------------------------------------------------------- #
# Import safety test                                                           #
# --------------------------------------------------------------------------- #

class TestImportSafety:

    def test_module_import_does_not_crash_when_env_empty(self, monkeypatch):
        """
        Importing gmail_auth must never crash even when no credentials are
        configured.  GmailAuthError is only raised when get_credentials()
        is called.
        """
        monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRETS_FILE", raising=False)
        monkeypatch.delenv("GOOGLE_OAUTH_TOKEN_FILE", raising=False)

        # Force reimport to verify import-time safety.
        mod_name = "app.services.mail.gmail_auth"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        try:
            import app.services.mail.gmail_auth  # noqa: F401
        except GmailAuthError:
            pytest.fail("gmail_auth must not raise GmailAuthError on import")
        except ImportError as exc:
            pytest.skip(f"Google libraries not installed: {exc}")
