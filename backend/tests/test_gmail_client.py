"""
Tests for GmailClient (app.services.mail.gmail_client).

No real Google credentials, internet access, or API calls are made.
All Google API interactions are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from app.services.mail.gmail_client import GmailClient, GmailClientError, _wrap_api_error


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #

def _make_client() -> tuple[GmailClient, MagicMock]:
    """
    Create a GmailClient with a fully mocked underlying Google API service.

    Returns:
        (client, mock_service) — the client and the mock service object.
    """
    mock_service = MagicMock()

    with patch(
        "app.services.mail.gmail_client.GmailClient._build_service",
        return_value=mock_service,
    ):
        client = GmailClient(credentials=MagicMock())

    return client, mock_service


# --------------------------------------------------------------------------- #
# Construction tests                                                           #
# --------------------------------------------------------------------------- #

class TestGmailClientConstruction:

    def test_build_service_called_on_init(self):
        mock_service = MagicMock()
        with patch(
            "app.services.mail.gmail_client.GmailClient._build_service",
            return_value=mock_service,
        ) as mock_build:
            client = GmailClient(credentials=MagicMock())
        mock_build.assert_called_once()
        assert client._service is mock_service

    def test_build_service_error_raises_gmail_client_error(self):
        with patch(
            "googleapiclient.discovery.build",
            side_effect=Exception("connection refused"),
        ):
            with pytest.raises(GmailClientError) as exc_info:
                GmailClient(credentials=MagicMock())
            assert "connection refused" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# get_profile tests                                                             #
# --------------------------------------------------------------------------- #

class TestGetProfile:

    def test_returns_profile_dict(self):
        client, mock_service = _make_client()
        expected = {
            "emailAddress": "test@example.com",
            "messagesTotal": 42,
            "threadsTotal": 10,
            "historyId": "9999",
        }
        mock_service.users().getProfile().execute.return_value = expected

        result = client.get_profile()
        assert result == expected

    def test_get_profile_calls_correct_endpoint(self):
        client, mock_service = _make_client()
        mock_service.users().getProfile().execute.return_value = {"emailAddress": "a@b.com"}

        client.get_profile()
        mock_service.users().getProfile.assert_called_with(userId="me")

    def test_get_profile_api_error_raises_gmail_client_error(self):
        client, mock_service = _make_client()
        mock_service.users().getProfile().execute.side_effect = Exception("403 Forbidden")

        with pytest.raises(GmailClientError):
            client.get_profile()


# --------------------------------------------------------------------------- #
# list_recent_messages tests                                                   #
# --------------------------------------------------------------------------- #

class TestListRecentMessages:

    def test_returns_message_list(self):
        client, mock_service = _make_client()
        expected = {
            "messages": [{"id": "msg1", "threadId": "th1"}, {"id": "msg2", "threadId": "th2"}],
            "resultSizeEstimate": 2,
        }
        mock_service.users().messages().list().execute.return_value = expected

        result = client.list_recent_messages(max_results=2)
        assert result == expected
        assert len(result["messages"]) == 2

    def test_default_max_results_is_10(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {"messages": []}

        client.list_recent_messages()
        mock_service.users().messages().list.assert_called_with(userId="me", maxResults=10)

    def test_custom_max_results(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {"messages": []}

        client.list_recent_messages(max_results=50)
        call_kwargs = mock_service.users().messages().list.call_args[1]
        assert call_kwargs["maxResults"] == 50

    def test_label_ids_passed_when_provided(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {"messages": []}

        client.list_recent_messages(label_ids=["INBOX", "UNREAD"])
        call_kwargs = mock_service.users().messages().list.call_args[1]
        assert call_kwargs["labelIds"] == ["INBOX", "UNREAD"]

    def test_page_token_passed_when_provided(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {}

        client.list_recent_messages(page_token="tok123")
        call_kwargs = mock_service.users().messages().list.call_args[1]
        assert call_kwargs["pageToken"] == "tok123"

    def test_query_passed_when_provided(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {}

        client.list_recent_messages(query="from:evil@example.com")
        call_kwargs = mock_service.users().messages().list.call_args[1]
        assert call_kwargs["q"] == "from:evil@example.com"

    def test_empty_result_set(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.return_value = {
            "resultSizeEstimate": 0
        }

        result = client.list_recent_messages()
        assert result.get("messages", []) == []

    def test_api_error_raises_gmail_client_error(self):
        client, mock_service = _make_client()
        mock_service.users().messages().list().execute.side_effect = Exception("quota exceeded")

        with pytest.raises(GmailClientError) as exc_info:
            client.list_recent_messages()
        assert "quota exceeded" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# get_message tests                                                            #
# --------------------------------------------------------------------------- #

class TestGetMessage:

    def test_returns_message_dict_full_format(self):
        client, mock_service = _make_client()
        expected = {
            "id": "msgABC",
            "threadId": "thrXYZ",
            "payload": {"headers": [], "body": {"data": ""}},
            "sizeEstimate": 512,
        }
        mock_service.users().messages().get().execute.return_value = expected

        result = client.get_message("msgABC", fmt="full")
        assert result["id"] == "msgABC"
        assert result["threadId"] == "thrXYZ"

    def test_get_message_calls_correct_endpoint(self):
        client, mock_service = _make_client()
        mock_service.users().messages().get().execute.return_value = {"id": "m1", "threadId": "t1"}

        client.get_message("m1", fmt="full")
        mock_service.users().messages().get.assert_called_with(
            userId="me", id="m1", format="full"
        )

    def test_metadata_format_allowed(self):
        client, mock_service = _make_client()
        mock_service.users().messages().get().execute.return_value = {"id": "m1", "threadId": "t1"}

        result = client.get_message("m1", fmt="metadata")
        assert result is not None

    def test_minimal_format_allowed(self):
        client, mock_service = _make_client()
        mock_service.users().messages().get().execute.return_value = {"id": "m1", "threadId": "t1"}

        result = client.get_message("m1", fmt="minimal")
        assert result is not None

    def test_raw_format_raises_gmail_client_error(self):
        """
        PRIVACY TEST: The 'raw' format fetches the full RFC 2822 MIME message.
        MAILTRACE must never use this format — raw MIME is never fetched.
        """
        client, mock_service = _make_client()

        with pytest.raises(GmailClientError) as exc_info:
            client.get_message("m1", fmt="raw")

        assert "raw" in str(exc_info.value).lower()
        assert "not permitted" in str(exc_info.value).lower()
        # The API must NOT have been called.
        mock_service.users().messages().get.assert_not_called()

    def test_api_error_raises_gmail_client_error(self):
        client, mock_service = _make_client()
        mock_service.users().messages().get().execute.side_effect = Exception("404 Not Found")

        with pytest.raises(GmailClientError):
            client.get_message("missing-id")

    def test_default_format_is_full(self):
        client, mock_service = _make_client()
        mock_service.users().messages().get().execute.return_value = {"id": "m1", "threadId": "t1"}

        client.get_message("m1")
        call_kwargs = mock_service.users().messages().get.call_args[1]
        assert call_kwargs["format"] == "full"


# --------------------------------------------------------------------------- #
# get_thread tests                                                              #
# --------------------------------------------------------------------------- #

class TestGetThread:

    def test_returns_thread_dict(self):
        client, mock_service = _make_client()
        expected = {
            "id": "thread123",
            "messages": [{"id": "m1"}, {"id": "m2"}],
        }
        mock_service.users().threads().get().execute.return_value = expected

        result = client.get_thread("thread123")
        assert result["id"] == "thread123"
        assert len(result["messages"]) == 2

    def test_api_error_raises_gmail_client_error(self):
        client, mock_service = _make_client()
        mock_service.users().threads().get().execute.side_effect = Exception("500 Server Error")

        with pytest.raises(GmailClientError):
            client.get_thread("any-thread-id")


# --------------------------------------------------------------------------- #
# _wrap_api_error tests                                                        #
# --------------------------------------------------------------------------- #

class TestWrapApiError:

    def test_plain_exception_has_no_status_code(self):
        exc = ValueError("something went wrong")
        wrapped = _wrap_api_error(exc, "test_op")
        assert isinstance(wrapped, GmailClientError)
        assert wrapped.status_code is None

    def test_http_error_extracts_status_code(self):
        mock_exc = MagicMock()
        mock_exc.resp.status = "403"
        mock_exc.__str__ = lambda self: "403 Forbidden"

        wrapped = _wrap_api_error(mock_exc, "test_op")
        assert wrapped.status_code == 403

    def test_message_includes_operation_name(self):
        exc = RuntimeError("boom")
        wrapped = _wrap_api_error(exc, "get_profile")
        assert "get_profile" in wrapped.message
