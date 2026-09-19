"""
Tests for DKIM verifier (forensics.authentication.dkim).

Covers:
- valid signature (cryptographic RSA verification in memory)
- invalid signature (tampered body / signature mismatch)
- missing signature (no DKIM-Signature header)
- malformed signature (missing required tags)
- missing selector
- missing DNS public key (unavailable)
- multiple signatures (evaluation and aggregation)

All tests operate strictly in memory with zero disk writes and zero network calls.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from forensics.authentication.dkim import parse_dkim_tags, verify_dkim
from forensics.authentication.models import DkimResult
from forensics.authentication.spf import DnsResolverProtocol
from forensics.email_parser import parse_email


class MockDkimResolver:
    """Mock DNS resolver returning configured public key records."""

    def __init__(self, records: dict[str, list[str]] | None = None):
        self.records = {k.lower().rstrip("."): v for k, v in (records or {}).items()}

    def get_txt_records(self, domain: str) -> list[str]:
        return self.records.get(domain.lower().rstrip("."), [])

    def get_a_records(self, domain: str) -> list[str]:
        return []

    def get_mx_hosts(self, domain: str) -> list[str]:
        return []


@pytest.fixture(scope="module")
def rsa_key_pair():
    """Generate an in-memory 1024-bit RSA key pair for testing."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return priv_pem, pub_b64


class TestDkimVerifier:

    def test_missing_signature(self):
        raw = (
            "From: alice@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: No DKIM\r\n"
            "\r\n"
            "Hello world\r\n"
        )
        parsed = parse_email(raw)
        result = verify_dkim(parsed)

        assert isinstance(result, DkimResult)
        assert result.status == "missing"
        assert len(result.signatures) == 0
        assert result.primary_domain is None

    def test_malformed_signature_missing_required_tags(self):
        # Missing s= and bh=
        raw = (
            "From: alice@example.com\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; b=AAAA;\r\n"
            "\r\n"
            "Hello world\r\n"
        )
        parsed = parse_email(raw)
        result = verify_dkim(parsed)

        assert result.status == "malformed"
        assert len(result.signatures) == 1
        assert result.signatures[0].result == "malformed"
        assert result.signatures[0].signature_valid is False

    def test_unavailable_dns_public_key(self):
        raw = (
            "From: alice@example.com\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=AAAA; b=BBBB;\r\n"
            "\r\n"
            "Hello world\r\n"
        )
        parsed = parse_email(raw)
        # Empty DNS resolver returns no public key
        resolver = MockDkimResolver(records={})
        result = verify_dkim(parsed, resolver=resolver)

        assert result.status == "unavailable"
        assert len(result.signatures) == 1
        assert result.signatures[0].result == "unavailable"
        assert result.signatures[0].signature_valid is False
        assert "not found" in (result.signatures[0].error or "").lower()

    def test_valid_signature_verification(self, rsa_key_pair):
        import dkim

        priv_pem, pub_b64 = rsa_key_pair
        msg = b"From: alice@example.com\r\nSubject: Test\r\n\r\nHello World"
        sig_header = dkim.sign(msg, b"s1", b"example.com", priv_pem)
        signed_email = sig_header + msg

        parsed = parse_email(signed_email)
        resolver = MockDkimResolver(
            records={"s1._domainkey.example.com": [f"v=DKIM1; k=rsa; p={pub_b64}"]}
        )

        result = verify_dkim(parsed, raw_message=signed_email, resolver=resolver)

        assert result.status == "valid"
        assert result.primary_domain == "example.com"
        assert len(result.signatures) == 1
        assert result.signatures[0].result == "valid"
        assert result.signatures[0].signature_valid is True

    def test_invalid_signature_when_body_tampered(self, rsa_key_pair):
        import dkim

        priv_pem, pub_b64 = rsa_key_pair
        msg = b"From: alice@example.com\r\nSubject: Test\r\n\r\nOriginal Body"
        sig_header = dkim.sign(msg, b"s1", b"example.com", priv_pem)

        # Tamper with the body
        tampered_email = sig_header + b"From: alice@example.com\r\nSubject: Test\r\n\r\nTampered Body"

        parsed = parse_email(tampered_email)
        resolver = MockDkimResolver(
            records={"s1._domainkey.example.com": [f"v=DKIM1; k=rsa; p={pub_b64}"]}
        )

        result = verify_dkim(parsed, raw_message=tampered_email, resolver=resolver)

        assert result.status == "invalid"
        assert len(result.signatures) == 1
        assert result.signatures[0].result == "invalid"
        assert result.signatures[0].signature_valid is False

    def test_multiple_signatures_one_valid_one_invalid(self, rsa_key_pair):
        import dkim

        priv_pem, pub_b64 = rsa_key_pair
        msg = b"From: alice@example.com\r\nSubject: Multi\r\n\r\nBody text"

        # Valid signature for example.com
        sig1 = dkim.sign(msg, b"s1", b"example.com", priv_pem)

        # Bogus second signature for other.com
        sig2 = b"DKIM-Signature: v=1; a=rsa-sha256; d=other.com; s=s2; h=from; bh=fake; b=fake;\r\n"

        multi_signed = sig1 + sig2 + msg
        parsed = parse_email(multi_signed)

        resolver = MockDkimResolver(
            records={
                "s1._domainkey.example.com": [f"v=DKIM1; k=rsa; p={pub_b64}"],
                "s2._domainkey.other.com": ["v=DKIM1; k=rsa; p=badkey"],
            }
        )

        result = verify_dkim(parsed, raw_message=multi_signed, resolver=resolver)

        # If at least one is valid, overall status is valid
        assert result.status == "valid"
        assert result.primary_domain == "example.com"
        assert len(result.signatures) == 2
        assert result.signatures[0].result == "valid"
        assert result.signatures[1].result == "invalid"

    def test_parse_dkim_tags_helper(self):
        header = "v=1; a=rsa-sha256; d=example.com; s=s1; bh=abc123; b=xyz456;"
        tags = parse_dkim_tags(header)
        assert tags["v"] == "1"
        assert tags["a"] == "rsa-sha256"
        assert tags["d"] == "example.com"
        assert tags["s"] == "s1"
        assert tags["bh"] == "abc123"
        assert tags["b"] == "xyz456"
