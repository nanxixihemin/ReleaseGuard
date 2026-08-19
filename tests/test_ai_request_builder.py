from __future__ import annotations

from pathlib import Path

from releaseguard.ai.request_builder import build_analysis_request, build_finding_excerpt
from releaseguard.ai.schemas import MAX_FINDINGS_PER_REQUEST
from releaseguard.context import ProjectContext
from releaseguard.models import Finding, Severity


def _finding() -> Finding:
    return Finding(
        rule_id="RG-ENV-001",
        title="Production endpoint points to a loopback address",
        severity=Severity.HIGH,
        category="environment",
        file="src/config.py",
        line=3,
        evidence="API_URL=https://alice:password@example.test/api?token=query-value",
        explanation="The endpoint is not suitable for production.",
        recommendation="Use protected production configuration.",
    )


def test_request_uses_only_finding_local_lines_and_redacts_them(tmp_path: Path) -> None:
    source = tmp_path / "src" / "config.py"
    source.parent.mkdir()
    original = "\n".join(
        [
            "DO_NOT_SEND_BEFORE = 'sk-test-only-fixture-1234567890'",
            "context_before = True",
            "API_URL = 'http://alice:password@example.test/api?token=query-value'",
            "context_after = True",
            "DO_NOT_SEND_AFTER = '/home/alice/private.txt'",
        ]
    )
    source.write_text(original, encoding="utf-8")
    context = ProjectContext(tmp_path)

    request = build_analysis_request(context, [_finding()], context_lines=1)
    payload = request.findings[0]

    assert payload.excerpt is not None
    assert (payload.excerpt.start_line, payload.excerpt.end_line) == (2, 4)
    assert "context_before" in payload.excerpt.text
    assert "context_after" in payload.excerpt.text
    assert "DO_NOT_SEND_BEFORE" not in payload.excerpt.text
    assert "DO_NOT_SEND_AFTER" not in payload.excerpt.text
    assert "alice:password" not in payload.excerpt.text
    assert "query-value" not in payload.evidence
    assert source.read_text(encoding="utf-8") == original


def test_request_is_bounded_and_does_not_sample_findings_without_lines(tmp_path: Path) -> None:
    source = tmp_path / "src" / "config.py"
    source.parent.mkdir()
    source.write_text("one\ntwo\nthree\n", encoding="utf-8")
    context = ProjectContext(tmp_path)
    finding = _finding()
    no_location = finding.model_copy(update={"line": None})

    request = build_analysis_request(
        context,
        [finding] * (MAX_FINDINGS_PER_REQUEST + 5),
    )

    assert len(request.findings) == MAX_FINDINGS_PER_REQUEST
    assert build_finding_excerpt(context, no_location) is None
