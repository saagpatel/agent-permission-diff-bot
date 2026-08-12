from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_permission_diff_bot.cli import main
from agent_permission_diff_bot.model import Severity
from agent_permission_diff_bot.server_card_diff import build_server_card_report
from agent_permission_diff_bot.server_card_normalize import normalize_snapshot
from agent_permission_diff_bot.server_card_reporting import (
    render_server_card_human,
    render_server_card_markdown,
    render_server_card_sarif,
)
from agent_permission_diff_bot.server_card_schema import (
    explain_server_card_schema,
    server_card_json_schema,
    validate_server_card_json,
)
from agent_permission_diff_bot.server_card_sources import (
    ServerCardInputError,
    read_server_card_directory,
    read_server_card_file,
    read_server_card_git_ref,
)

FIXTURES = Path(__file__).parent / "fixtures" / "server_card"


def fixture(name: str) -> Path:
    return FIXTURES / name


def report_for(base: str, head: str, **kwargs: object):
    return build_server_card_report(
        read_server_card_file(fixture(base), label="base"),
        read_server_card_file(fixture(head), label="head"),
        **kwargs,
    )


def test_current_registry_cards_cover_security_and_surface_drift() -> None:
    report = report_for("current-base.server.json", "current-head.server.json")

    kinds = {change.kind for change in report.changes}
    categories = {change.category for change in report.changes}
    secret_marker = next(change for change in report.changes if change.path.endswith(".is_secret"))

    assert {"added", "removed", "widened", "changed"} <= kinds
    assert {
        "authentication",
        "capability",
        "endpoint",
        "package_provenance",
        "transport",
    } <= categories
    assert secret_marker.severity is Severity.CRITICAL
    assert "runtime behavior remains UNKNOWN" in secret_marker.explanation


def test_protocol_discovery_narrowing_is_breaking_and_separate_from_registry() -> None:
    report = report_for(
        "protocol-discovery-base.server.json", "protocol-discovery-head.server.json"
    )
    versions = next(
        change for change in report.changes if change.path == "compatibility.supported_versions"
    )

    assert versions.kind == "narrowed"
    assert versions.severity is Severity.HIGH
    assert versions.standard is True
    assert versions.source_contracts == ("mcp_protocol_2026-07-28:server/discover",)


def test_reorder_only_and_identical_snapshots_are_stable() -> None:
    reordered = report_for("reorder-base.server.json", "reorder-head.server.json")
    identical_a = report_for("identical.server.json", "identical.server.json")
    identical_b = report_for("identical.server.json", "identical.server.json")

    assert reordered.changes == []
    assert identical_a.changes == []
    assert identical_a.report_id == identical_b.report_id
    assert identical_a.to_dict() == identical_b.to_dict()


def test_schema_versions_missing_data_and_registry_wrapper_are_classified() -> None:
    legacy = normalize_snapshot(read_server_card_file(fixture("legacy-schema.server.json")))[0]
    missing = normalize_snapshot(read_server_card_file(fixture("missing-data.server.json")))[0]
    wrapped = normalize_snapshot(read_server_card_file(fixture("registry-response.server.json")))[0]

    assert legacy.schema_status == "recognized"
    assert legacy.validity == "valid"
    assert missing.validity == "partial"
    assert any("description" in issue for issue in missing.issues)
    assert wrapped.contract_family == "mcp_registry_api"
    assert "registry.official.status" in wrapped.field_map


def test_unknown_schema_and_malformed_card_preserve_unknown_not_absence() -> None:
    unknown = normalize_snapshot(read_server_card_file(fixture("unknown-schema.server.json")))[0]
    malformed_report = report_for("malformed.server.json", "identical.server.json")

    assert unknown.schema_status == "unknown"
    assert unknown.validity == "partial"
    assert any(change.kind == "unknown" for change in malformed_report.changes)
    assert malformed_report.normalized_base[0].validity == "invalid"


def test_vendor_aliases_remain_extension_claims() -> None:
    card = normalize_snapshot(read_server_card_file(fixture("vendor-aliases.server.json")))[0]

    assert card.contract_family == "vendor_server_card"
    assert card.fields
    assert all(field.standard is False for field in card.fields)
    assert any(field.contract == "vendor_extension" for field in card.fields)
    assert not any(field.path == "identity.name" for field in card.fields)


def test_secret_values_never_render_in_any_output() -> None:
    report = report_for("current-base.server.json", "current-head.server.json")
    payloads = (
        json.dumps(report.to_dict(), sort_keys=True),
        render_server_card_human(report),
        render_server_card_markdown(report),
        json.dumps(render_server_card_sarif(report), sort_keys=True),
    )

    for payload in payloads:
        assert "fixture-token-should-never-render" not in payload
        assert "changed-fixture-token-should-never-render" not in payload
        assert "base-private-extension-value" not in payload
        assert "head-private-extension-value" not in payload
    assert any("[REDACTED]" in payload for payload in payloads)


def test_standard_url_display_redacts_userinfo_and_query_values(tmp_path: Path) -> None:
    base = tmp_path / "base.server.json"
    head = tmp_path / "head.server.json"
    template: dict[str, object] = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.example/url-redaction",
        "description": "URL redaction fixture",
        "version": "1.0.0",
        "remotes": [],
    }
    base.write_text(json.dumps(template), encoding="utf-8")
    template["remotes"] = [
        {
            "type": "streamable-http",
            "url": "https://user:password@example.test/mcp?token=very-secret&region=us",
        }
    ]
    head.write_text(json.dumps(template), encoding="utf-8")

    report = build_server_card_report(read_server_card_file(base), read_server_card_file(head))
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert "password" not in rendered
    assert "very-secret" not in rendered
    assert "%5BREDACTED%5D" in rendered


def test_schema_uri_redacts_credentials_without_losing_safe_identity(tmp_path: Path) -> None:
    card_path = tmp_path / "credentialed-schema.server.json"
    card_path.write_text(
        json.dumps(
            {
                "$schema": (
                    "https://schema-user:schema-password@schemas.example.test/vendor/"
                    "server.schema.json?token=schema-secret&region=west"
                ),
                "name": "io.example/credentialed-schema",
                "description": "Credential-bearing schema URI fixture",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )

    card = normalize_snapshot(read_server_card_file(card_path))[0]
    rendered = json.dumps(card.to_summary_dict(), sort_keys=True)

    assert card.schema_uri == (
        "https://[REDACTED]@schemas.example.test/vendor/server.schema.json?"
        "token=%5BREDACTED%5D&region=%5BREDACTED%5D"
    )
    assert "schemas.example.test/vendor/server.schema.json" in rendered
    assert "schema-user" not in rendered
    assert "schema-password" not in rendered
    assert "schema-secret" not in rendered
    assert "west" not in rendered
    assert card.issues == (f"Unrecognized declared schema URI: {card.schema_uri}",)


def test_safe_unknown_schema_uri_identity_is_preserved(tmp_path: Path) -> None:
    card_path = tmp_path / "safe-schema.server.json"
    schema_uri = "https://schemas.example.test/vendor/server.schema.json"
    card_path.write_text(
        json.dumps(
            {
                "$schema": schema_uri,
                "name": "io.example/safe-schema",
                "description": "Safe schema URI fixture",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )

    card = normalize_snapshot(read_server_card_file(card_path))[0]

    assert card.schema_uri == schema_uri
    assert card.issues == (f"Unrecognized declared schema URI: {schema_uri}",)


@pytest.mark.parametrize(
    "schema_uri",
    [
        "mcp+registry://api-user:api-password@schemas.example.test/card?token=api-secret",
        "urn:example:mcp-card?token=urn-secret",
    ],
)
def test_schema_uri_redacts_credentials_across_uri_forms(tmp_path: Path, schema_uri: str) -> None:
    card_path = tmp_path / "alternate-schema.server.json"
    card_path.write_text(
        json.dumps(
            {
                "$schema": schema_uri,
                "name": "io.example/alternate-schema",
                "description": "Alternate credential-bearing URI fixture",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )

    rendered = json.dumps(
        normalize_snapshot(read_server_card_file(card_path))[0].to_summary_dict(), sort_keys=True
    )

    assert "api-user" not in rendered
    assert "api-password" not in rendered
    assert "api-secret" not in rendered
    assert "urn-secret" not in rendered
    assert "%5BREDACTED%5D" in rendered


def test_directory_and_git_ref_inputs_are_offline_and_provenance_preserving(
    tmp_path: Path,
) -> None:
    base_dir = tmp_path / "base"
    head_dir = tmp_path / "head"
    base_dir.mkdir()
    head_dir.mkdir()
    (base_dir / "server.json").write_text(
        fixture("identical.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (head_dir / "server.json").write_text(
        fixture("current-head.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    directory = read_server_card_directory(base_dir)
    assert directory.kind == "directory"
    assert directory.cards[0].provenance.path == "server.json"

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.test")
    (repo / "server.json").write_text(
        fixture("identical.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    _git(repo, "add", "server.json")
    _git(repo, "commit", "-qm", "base")
    base_ref = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "server.json").write_text(
        fixture("current-head.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    _git(repo, "add", "server.json")
    _git(repo, "commit", "-qm", "head")
    head_ref = _git(repo, "rev-parse", "HEAD").strip()

    base = read_server_card_git_ref(repo, base_ref)
    head = read_server_card_git_ref(repo, head_ref)
    report = build_server_card_report(base, head)
    assert base.cards[0].provenance.git_ref == base_ref
    assert head.cards[0].provenance.git_ref == head_ref
    assert report.changes


def test_directory_discovery_rejects_symlink_escape_and_accepts_contained_symlink(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.server.json"
    outside.write_text(
        fixture("identical.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    escaped_root = tmp_path / "escaped"
    escaped_root.mkdir()
    (escaped_root / "leak.server.json").symlink_to(outside)

    with pytest.raises(ServerCardInputError, match="escapes snapshot root"):
        read_server_card_directory(escaped_root)

    contained_root = tmp_path / "contained"
    contained_root.mkdir()
    contained = contained_root / "real.server.json"
    contained.write_text(
        fixture("identical.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (contained_root / "alias.server.json").symlink_to(contained)

    snapshot = read_server_card_directory(contained_root)

    assert len(snapshot.cards) == 1
    assert snapshot.cards[0].provenance.path == "real.server.json"


def test_explicit_git_card_can_be_added_or_removed_between_refs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.test")
    _git(repo, "commit", "--allow-empty", "-qm", "base")
    absent_ref = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "custom-card.json").write_text(
        fixture("identical.server.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    _git(repo, "add", "custom-card.json")
    _git(repo, "commit", "-qm", "add card")
    present_ref = _git(repo, "rev-parse", "HEAD").strip()

    absent = read_server_card_git_ref(repo, absent_ref, card_paths=("custom-card.json",))
    present = read_server_card_git_ref(repo, present_ref, card_paths=("custom-card.json",))

    assert absent.cards == ()
    assert [change.kind for change in build_server_card_report(absent, present).changes] == [
        "added"
    ]
    assert [change.kind for change in build_server_card_report(present, absent).changes] == [
        "removed"
    ]

    added_json = tmp_path / "added.json"
    assert (
        main(
            [
                "server-card-diff",
                "--repo",
                str(repo),
                "--base-ref",
                absent_ref,
                "--head-ref",
                present_ref,
                "--card-path",
                "custom-card.json",
                "--json",
                str(added_json),
            ]
        )
        == 0
    )
    assert json.loads(added_json.read_text(encoding="utf-8"))["changes"][0]["kind"] == "added"

    removed_json = tmp_path / "removed.json"
    assert (
        main(
            [
                "server-card-diff",
                "--repo",
                str(repo),
                "--base-ref",
                present_ref,
                "--head-ref",
                absent_ref,
                "--card-path",
                "custom-card.json",
                "--json",
                str(removed_json),
            ]
        )
        == 0
    )
    assert json.loads(removed_json.read_text(encoding="utf-8"))["changes"][0]["kind"] == "removed"


def test_cli_rejects_explicit_git_card_missing_from_both_refs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.test")
    _git(repo, "commit", "--allow-empty", "-qm", "base")
    ref = _git(repo, "rev-parse", "HEAD").strip()

    with pytest.raises(SystemExit, match="not found in either Git ref"):
        main(
            [
                "server-card-diff",
                "--repo",
                str(repo),
                "--base-ref",
                ref,
                "--head-ref",
                ref,
                "--card-path",
                "missing-card.json",
            ]
        )


def test_cli_writes_human_json_markdown_sarif_and_validates_report(tmp_path: Path) -> None:
    human = tmp_path / "report.txt"
    output = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    sarif = tmp_path / "report.sarif"

    code = main(
        [
            "server-card-diff",
            "--base-file",
            str(fixture("current-base.server.json")),
            "--head-file",
            str(fixture("current-head.server.json")),
            "--human",
            str(human),
            "--json",
            str(output),
            "--markdown",
            str(markdown),
            "--sarif",
            str(sarif),
            "--mode",
            "observe",
        ]
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    sarif_payload = json.loads(sarif.read_text(encoding="utf-8"))

    assert code == 0
    assert validate_server_card_json(payload, "report")["valid"] is True
    assert "MCP Server Card Drift Examiner" in human.read_text(encoding="utf-8")
    assert "# MCP Server Card Drift" in markdown.read_text(encoding="utf-8")
    assert sarif_payload["version"] == "2.1.0"


def test_gate_exit_behavior_matches_existing_conventions() -> None:
    observe = report_for(
        "current-base.server.json",
        "current-head.server.json",
        mode="observe",
        fail_on=Severity.HIGH,
    )
    enforce = report_for(
        "current-base.server.json",
        "current-head.server.json",
        mode="enforce",
        fail_on=Severity.HIGH,
    )

    assert observe.gate is not None and observe.gate.exit_code == 0
    assert observe.gate.status == "observe"
    assert enforce.gate is not None and enforce.gate.exit_code == 2
    assert enforce.gate.status == "fail"


def test_schema_explanation_export_and_validation_are_static() -> None:
    contract = explain_server_card_schema()
    report_schema = server_card_json_schema("report")
    contract_schema = server_card_json_schema("contract")

    assert contract["network_default"] == "off"
    assert contract["runtime_observation"] == "UNKNOWN"
    assert contract["standards"]["registry"]["commit"]
    assert report_schema["$id"].endswith("mcp-server-card-drift-report-v1.json")
    assert contract_schema["properties"]["contract_version"]["const"] == "1.0.0"
    assert validate_server_card_json(contract, "contract")["valid"] is True
    checked_in = json.loads(
        (
            Path(__file__).parents[1] / "schemas" / "mcp-server-card-drift-report-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert checked_in == report_schema


@pytest.mark.parametrize(
    ("path", "corrupt"),
    [
        (("contract_version",), lambda value: "0.0.0"),
        (("safety_boundary",), lambda value: None),
        (("standards",), lambda value: None),
        (("inputs", "base", "card_count"), lambda value: "1"),
        (("inputs", "head", "cards", 0, "sha256"), lambda value: "not-a-sha256"),
        (("normalized_cards", "base", 0, "provenance"), lambda value: None),
        (("normalized_cards", "head", 0, "schema_status"), lambda value: "trusted"),
        (("summary", "kinds", "changed"), lambda value: "many"),
        (("gate", "threshold_met"), lambda value: "true"),
        (("changes", 0, "base", "display"), lambda value: None),
    ],
)
def test_report_validation_rejects_corrupt_nested_contract(
    path: tuple[str | int, ...], corrupt: Callable[[object], object]
) -> None:
    payload = report_for("current-base.server.json", "current-head.server.json").to_dict()
    target: object = payload
    for segment in path[:-1]:
        target = target[segment]  # type: ignore[index]
    final = path[-1]
    target[final] = corrupt(target[final])  # type: ignore[index,operator]

    result = validate_server_card_json(payload, "report")

    assert result["valid"] is False
    assert result["errors"]


def test_cli_report_validation_failure_reports_nested_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = report_for("current-base.server.json", "current-head.server.json").to_dict()
    payload["normalized_cards"]["head"][0]["issues"] = None
    invalid = tmp_path / "invalid-nested.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")

    assert (
        main(
            [
                "server-card-diff",
                "--validate-json",
                str(invalid),
                "--schema",
                "report",
            ]
        )
        == 2
    )
    validation = json.loads(capsys.readouterr().out)
    assert any("$.normalized_cards.head[0].issues" in error for error in validation["errors"])


def test_cli_schema_introspection_does_not_require_snapshot_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["server-card-diff", "--explain-schema"]) == 0
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["network_default"] == "off"

    assert main(["server-card-diff", "--json-schema", "report"]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["$id"].endswith("mcp-server-card-drift-report-v1.json")


def test_no_network_default_even_when_socket_is_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def deny_network(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"network attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    output = tmp_path / "offline.json"
    code = main(
        [
            "server-card-diff",
            "--base-file",
            str(fixture("identical.server.json")),
            "--head-file",
            str(fixture("identical.server.json")),
            "--json",
            str(output),
        ]
    )

    assert code == 0
    assert output.exists()


def test_cli_report_validation_failure_exits_two(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version":"999"}', encoding="utf-8")

    assert (
        main(
            [
                "server-card-diff",
                "--validate-json",
                str(invalid),
                "--schema",
                "report",
            ]
        )
        == 2
    )


def test_snapshot_path_and_ref_injection_inputs_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    outside = tmp_path / "outside.server.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ServerCardInputError, match="escapes snapshot root"):
        read_server_card_directory(root, card_paths=("../outside.server.json",))

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    with pytest.raises(ServerCardInputError, match="non-option"):
        read_server_card_git_ref(repo, "--help", card_paths=("server.json",))
    with pytest.raises(ServerCardInputError, match="clean relative Git path"):
        read_server_card_git_ref(repo, "HEAD", card_paths=("../server.json",))


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
