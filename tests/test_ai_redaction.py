from __future__ import annotations

from releaseguard.ai.redaction import (
    REDACTED_PATH,
    REDACTED_PRIVATE_KEY,
    REDACTED_QUERY,
    REDACTED_SECRET,
    REDACTED_TOKEN,
    REDACTED_URL,
    TRUNCATION_MARKER,
    redact_and_truncate,
    redact_text,
    truncate_text,
)


def test_redact_text_removes_tokens_urls_userinfo_queries_and_absolute_paths() -> None:
    # Nonfunctional test-only strings exercise every redaction boundary.
    openai_key = "sk-test-only-fixture-1234567890"
    bearer = "Bearer abcdefghijklmnop"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturevalue"
    raw = (
        f"OPENAI_API_KEY={openai_key} {bearer} {jwt} "
        "PASSWORD=plain-secret "
        "postgres://alice:password@example.test/release?token=query-value "
        r"C:\Users\Alice\project\config.py /home/alice/project/config.py"
    )

    redacted = redact_text(raw)

    for sensitive in (openai_key, "abcdefghijklmnop", jwt, "alice:password", "query-value", "Alice"):
        assert sensitive not in redacted
    assert REDACTED_SECRET in redacted
    assert REDACTED_TOKEN in redacted
    assert REDACTED_URL in redacted
    assert REDACTED_PATH in redacted


def test_redaction_preserves_no_private_key_material() -> None:
    raw = "-----BEGIN PRIVATE KEY-----\nvery-secret-body\n-----END PRIVATE KEY-----"

    redacted = redact_text(raw)

    assert "very-secret-body" not in redacted
    assert REDACTED_PRIVATE_KEY in redacted
    assert redacted.count("\n") == raw.count("\n")


def test_redaction_happens_before_truncation() -> None:
    raw = "prefix " + "sk-test-only-fixture-1234567890" + " suffix " + ("x" * 100)

    result = redact_and_truncate(raw, max_length=48)

    assert "sk-test-only-fixture-1234567890" not in result
    assert REDACTED_TOKEN in result
    assert len(result) <= 48
    assert result.endswith(TRUNCATION_MARKER)
    assert truncate_text("short", max_length=16) == "short"


def test_redaction_retains_sanitized_localhost_endpoint_shape() -> None:
    raw = "API_URL=http://alice:password@localhost:8080/api?token=secret&mode=debug#fragment"

    redacted = redact_text(raw)

    assert "http://localhost:8080/api" in redacted
    assert "alice:password" not in redacted
    assert "secret" not in redacted
    assert "fragment" not in redacted
    assert REDACTED_QUERY in redacted
