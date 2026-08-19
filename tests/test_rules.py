from __future__ import annotations

from pathlib import Path

from releaseguard.context import ProjectContext
from releaseguard.models import Severity
from releaseguard.rules.artifacts import ArtifactRule
from releaseguard.rules.debug import DebugRule
from releaseguard.rules.environment import EnvironmentRule
from releaseguard.rules.release_config import ReleaseConfigRule
from releaseguard.rules.secrets import SecretRule
from releaseguard.rules.sensitive_files import SensitiveFilesRule
from releaseguard.rules.todos import TodoRule


def _findings(rule: object, root: Path):
    return rule.check(ProjectContext(root))


def test_secret_rule_masks_openai_style_key_and_avoids_generic_wording(tmp_path: Path) -> None:
    raw_secret = "sk-FAKE_RELEASE_GUARD_1234567890"
    (tmp_path / "settings.py").write_text(
        f'OPENAI_API_KEY = "{raw_secret}"\nmessage = "password"\n', encoding="utf-8"
    )

    findings = _findings(SecretRule(), tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "RG-SECRET-001"
    assert finding.severity is Severity.CRITICAL
    assert raw_secret not in finding.evidence
    assert "sk-" in finding.evidence
    assert finding.file == "settings.py"
    assert finding.fingerprint


def test_secret_rule_accepts_literal_assignment_but_rejects_code_expression(tmp_path: Path) -> None:
    literal = "AbC1234Def5678Ghi9012Jkl"
    (tmp_path / "settings.ts").write_text(
        f'const API_KEY = "{literal}";\ntoken = match.group("token")\n', encoding="utf-8"
    )

    findings = _findings(SecretRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].title == "High-entropy credential assignment detected"
    assert literal not in findings[0].evidence


def test_secret_rule_detects_short_mixed_password_but_not_plain_word(tmp_path: Path) -> None:
    raw_password = "Release9!"
    (tmp_path / "settings.py").write_text(
        f'DB_PASSWORD = "{raw_password}"\nPASSWORD = "development"\n', encoding="utf-8"
    )

    findings = _findings(SecretRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].title == "Potential password assignment detected"
    assert raw_password not in findings[0].evidence


def test_environment_rule_raises_production_loopback_but_not_readme(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'PRODUCTION_API_URL = "http://localhost:8080"\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("Run locally at http://localhost:8080\n", encoding="utf-8")

    findings = _findings(EnvironmentRule(), tmp_path)

    by_file = {finding.file: finding for finding in findings}
    assert by_file["config.py"].severity is Severity.CRITICAL
    assert by_file["README.md"].severity is Severity.LOW


def test_environment_rule_ignores_endpoint_regex_definitions(tmp_path: Path) -> None:
    (tmp_path / "matcher.py").write_text(
        'LOOPBACK = re.compile(r"localhost|127\\.0\\.0\\.1")\n', encoding="utf-8"
    )

    assert _findings(EnvironmentRule(), tmp_path) == []


def test_environment_rule_masks_endpoint_userinfo_and_sensitive_query_values(tmp_path: Path) -> None:
    raw_password = "LocalPassword123!"
    raw_token = "sk-FAKE_URL_TOKEN_1234567890"
    (tmp_path / "config.py").write_text(
        (
            'PRODUCTION_API_URL = "http://operator:'
            f"{raw_password}@localhost:8080/api?token={raw_token}&ref={raw_token}&mode=release" + '"\n'
        ),
        encoding="utf-8",
    )

    finding = _findings(EnvironmentRule(), tmp_path)[0]

    assert finding.severity is Severity.CRITICAL
    assert raw_password not in finding.evidence
    assert raw_token not in finding.evidence
    assert "***@localhost" in finding.evidence
    assert "token=***" in finding.evidence
    assert "ref=***" in finding.evidence


def test_debug_rule_detects_enabled_debug_mode(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")

    findings = _findings(DebugRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "RG-DEBUG-001"
    assert findings[0].severity is Severity.HIGH


def test_debug_rule_detects_android_debuggable_configuration(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("android { buildTypes { release { debuggable true } } }\n", encoding="utf-8")

    findings = _findings(DebugRule(), tmp_path)

    assert any(finding.metadata["debug_setting"] == "android_debuggable" for finding in findings)
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_todo_rule_escalates_permission_work_but_not_a_simple_note(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "auth.py").write_text("# TODO: verify user permission before release\n", encoding="utf-8")
    (source / "ui.py").write_text("# TODO: improve button copy\n", encoding="utf-8")

    findings = _findings(TodoRule(), tmp_path)

    by_file = {finding.file: finding for finding in findings}
    assert by_file["src/auth.py"].severity is Severity.HIGH
    assert by_file["src/ui.py"].severity is Severity.LOW


def test_todo_rule_ignores_marker_names_in_strings_and_documentation(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text(
        'marker_names = "TODO FIXME HACK XXX"\n# TODO: resolve the actual review item\n',
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("TODO: this is documentation prose\n", encoding="utf-8")

    findings = _findings(TodoRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "source.py"


def test_todo_rule_detects_inline_comment_but_not_quoted_marker(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text(
        'deploy(); // TODO: confirm rollout\nlabel = "// TODO: not an action"\n',
        encoding="utf-8",
    )

    findings = _findings(TodoRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].evidence == "TODO marker"


def test_todo_rule_never_reports_secret_like_detail(tmp_path: Path) -> None:
    raw_secret = "sk-FAKE_TODO_DETAIL_1234567890"
    (tmp_path / "src.py").write_text(f"# TODO: rotate {raw_secret}\n", encoding="utf-8")

    finding = _findings(TodoRule(), tmp_path)[0]

    assert raw_secret not in finding.evidence
    assert finding.evidence == "TODO marker"


def test_sensitive_environment_file_uses_content_heuristic(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=local_value_12345\n", encoding="utf-8")

    findings = _findings(SensitiveFilesRule(), tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "RG-SENSITIVE-001"
    assert findings[0].severity is Severity.HIGH
    assert "local_value_12345" not in findings[0].evidence


def test_release_config_rule_detects_missing_metadata_and_docker_dev_command(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    (tmp_path / "Dockerfile").write_text('CMD ["npm", "run", "dev"]\n', encoding="utf-8")

    findings = _findings(ReleaseConfigRule(), tmp_path)

    assert any(
        finding.rule_id == "RG-CONFIG-001" and finding.severity is Severity.MEDIUM
        for finding in findings
    )
    assert any(
        finding.rule_id == "RG-CONFIG-002" and finding.severity is Severity.HIGH
        for finding in findings
    )


def test_artifact_rule_detects_files_without_traversing_ide_directory(tmp_path: Path) -> None:
    (tmp_path / ".DS_Store").write_text("metadata", encoding="utf-8")
    (tmp_path / "runtime.sqlite3").write_text("database", encoding="utf-8")
    (tmp_path / "server.log").write_text("log", encoding="utf-8")
    (tmp_path / "notes.tmp").write_text("temporary", encoding="utf-8")
    (tmp_path / "profile.heapsnapshot").write_text("profiling data", encoding="utf-8")
    idea = tmp_path / ".idea"
    idea.mkdir()
    (idea / "workspace.xml").write_text("ignored content", encoding="utf-8")
    build_temp = tmp_path / "build" / "tmp"
    build_temp.mkdir(parents=True)

    findings = _findings(ArtifactRule(), tmp_path)

    by_file = {finding.file: finding for finding in findings}
    assert by_file["runtime.sqlite3"].severity is Severity.MEDIUM
    assert by_file[".DS_Store"].severity is Severity.LOW
    assert by_file["server.log"].severity is Severity.LOW
    assert by_file["notes.tmp"].severity is Severity.LOW
    assert by_file["profile.heapsnapshot"].severity is Severity.MEDIUM
    assert by_file[".idea"].severity is Severity.LOW
    assert by_file["build/tmp"].severity is Severity.LOW
    assert all("workspace.xml" not in finding.file for finding in findings)
