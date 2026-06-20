from __future__ import annotations

from collections import defaultdict

from agent_permission_diff_bot.model import (
    Finding,
    PermissionAtom,
    PermissionChange,
    PermissionDiffReport,
    Severity,
)
from agent_permission_diff_bot.surfaces import extract_atoms


def build_report(
    base_label: str,
    base_files: dict[str, str],
    head_label: str,
    head_files: dict[str, str],
) -> PermissionDiffReport:
    base_atoms = _extract_snapshot_atoms(base_files)
    head_atoms = _extract_snapshot_atoms(head_files)
    changes = diff_atoms(base_atoms, head_atoms)
    findings = correlate(changes)
    return PermissionDiffReport(
        base=base_label, head=head_label, changes=changes, findings=findings
    )


def diff_atoms(
    base_atoms: list[PermissionAtom], head_atoms: list[PermissionAtom]
) -> list[PermissionChange]:
    base_by_key = {atom.key(): atom for atom in base_atoms}
    head_by_key = {atom.key(): atom for atom in head_atoms}

    changes: list[PermissionChange] = []
    for key, atom in sorted(head_by_key.items()):
        if key not in base_by_key:
            changes.append(PermissionChange(kind="added", atom=atom))
    for key, atom in sorted(base_by_key.items()):
        if key not in head_by_key:
            changes.append(PermissionChange(kind="removed", atom=atom))
    return changes


def correlate(changes: list[PermissionChange]) -> list[Finding]:
    added = [change for change in changes if change.kind == "added"]
    findings: list[Finding] = []

    findings.extend(_single_surface_findings(added))
    findings.extend(_composition_findings(added))
    return _dedupe_findings(findings)


def _extract_snapshot_atoms(files: dict[str, str]) -> list[PermissionAtom]:
    atoms: list[PermissionAtom] = []
    for path, text in files.items():
        atoms.extend(extract_atoms(path, text))
    return atoms


def _single_surface_findings(changes: list[PermissionChange]) -> list[Finding]:
    findings: list[Finding] = []
    for change in changes:
        atom = change.atom
        if atom.surface == "actions" and atom.resource == "self_hosted_runner":
            fork_reachable = (
                "pull_request" in atom.trigger and "pull_request.head.repo.fork" not in atom.value
            )
            severity = Severity.CRITICAL if fork_reachable else Severity.HIGH
            findings.append(
                Finding(
                    rule_id="APD001",
                    title="Self-hosted runner reach changed",
                    severity=severity,
                    summary=(
                        "A workflow job can now execute on a self-hosted runner"
                        + (" from pull request context." if fork_reachable else ".")
                    ),
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm untrusted PR code cannot reach the self-hosted runner."
                    ),
                )
            )
        elif (
            atom.surface == "actions"
            and atom.action == "token_permission"
            and atom.value == "id-token:write"
        ):
            findings.append(
                Finding(
                    rule_id="APD002",
                    title="OIDC token permission added",
                    severity=Severity.HIGH,
                    summary=(
                        "A workflow gained `id-token: write`, enabling cloud/provider "
                        "identity federation."
                    ),
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm this is paired with a protected, intended deployment path."
                    ),
                )
            )
        elif (
            atom.surface == "actions"
            and atom.action == "token_permission"
            and atom.verb
            in {
                "write",
                "write-all",
            }
        ):
            findings.append(
                Finding(
                    rule_id="APD003",
                    title="GitHub token write permission added",
                    severity=Severity.HIGH,
                    summary=f"A workflow gained write access for `{atom.resource}`.",
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm the job needs write scope and cannot run on untrusted input."
                    ),
                )
            )
        elif atom.surface == "mcp" and atom.action == "tool_allowlist" and atom.value == "*":
            severity = Severity.HIGH if atom.credential_keys else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id="APD004",
                    title="Broad MCP tool allowlist added",
                    severity=severity,
                    summary='An MCP server now allows all tools via `tools: ["*"]`.',
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm every tool exposed by this server is intended for autonomous use."
                    ),
                )
            )
        elif atom.surface == "egress" and atom.action == "allow_hosts":
            severity = Severity.HIGH if _host_is_multi_tenant(atom.value) else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id="APD005",
                    title="Egress host allowlist expanded",
                    severity=severity,
                    summary=f"A new outbound host is allowlisted: `{atom.value}`.",
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm this destination is owned, tenant-scoped, and intended."
                    ),
                )
            )
        elif atom.surface == "instructions" and atom.action == "instruction_weakening":
            findings.append(
                Finding(
                    rule_id="APD006",
                    title="Agent instruction weakens review controls",
                    severity=Severity.HIGH,
                    summary=(
                        "An agent instruction file now appears to weaken tests, review, "
                        "approval, or guardrails."
                    ),
                    evidence=[atom.evidence],
                    changes=[change],
                    reviewer_decision=(
                        "Confirm the instruction does not reduce required verification "
                        "or safety checks."
                    ),
                )
            )
    return findings


def _composition_findings(changes: list[PermissionChange]) -> list[Finding]:
    by_surface: dict[str, list[PermissionChange]] = defaultdict(list)
    for change in changes:
        by_surface[change.atom.surface].append(change)

    findings: list[Finding] = []
    mcp_broad = [
        c for c in by_surface["mcp"] if c.atom.action == "tool_allowlist" and c.atom.value == "*"
    ]
    mcp_creds = [c for c in by_surface["mcp"] if c.atom.action == "credential"]
    egress_hosts = [c for c in by_surface["egress"] if c.atom.action == "allow_hosts"]
    connector_allows = [c for c in by_surface["egress"] if c.atom.action == "allow_connectors"]
    deploys = [c for c in by_surface["actions"] if c.atom.action == "cloud_deploy"]
    oidc = [
        c
        for c in by_surface["actions"]
        if c.atom.action == "token_permission" and c.atom.value == "id-token:write"
    ]
    envs = [c for c in by_surface["actions"] if c.atom.action == "deployment_environment"]
    instruction_changes = by_surface["instructions"]

    if mcp_broad and (mcp_creds or egress_hosts):
        involved = [*mcp_broad, *mcp_creds, *egress_hosts]
        findings.append(
            Finding(
                rule_id="APD101",
                title="MCP autonomy expansion combines tools with credentials or egress",
                severity=Severity.HIGH,
                summary=(
                    "The PR combines broad MCP tool access with credential key references or new "
                    "egress destinations."
                ),
                evidence=_evidence(involved),
                changes=involved,
                reviewer_decision=(
                    "Review this as an autonomous capability expansion, not isolated config churn."
                ),
            )
        )

    if connector_allows and (egress_hosts or mcp_creds):
        involved = [*connector_allows, *egress_hosts, *mcp_creds]
        findings.append(
            Finding(
                rule_id="APD102",
                title="Connector write or allowlist change combines with egress or credentials",
                severity=Severity.HIGH,
                summary="The PR changes connector reach alongside a route or credential surface.",
                evidence=_evidence(involved),
                changes=involved,
                reviewer_decision=(
                    "Confirm the connector cannot become a trusted courier for unintended writes."
                ),
            )
        )

    if oidc and deploys and not envs:
        involved = [*oidc, *deploys]
        findings.append(
            Finding(
                rule_id="APD103",
                title="OIDC deploy path lacks visible environment protection",
                severity=Severity.HIGH,
                summary=(
                    "The PR adds OIDC-capable deployment behavior without a visible "
                    "GitHub environment."
                ),
                evidence=_evidence(involved),
                changes=involved,
                reviewer_decision=(
                    "Confirm deployment is constrained by environment protections or "
                    "external trust policy."
                ),
            )
        )

    high_expansions = [
        c
        for c in changes
        if c.atom.surface in {"mcp", "actions", "egress"}
        and (
            c.atom.action in {"tool_allowlist", "cloud_deploy", "allow_hosts", "allow_connectors"}
            or c.atom.value == "id-token:write"
            or c.atom.resource == "self_hosted_runner"
        )
    ]
    if instruction_changes and high_expansions:
        involved = [*instruction_changes, *high_expansions]
        findings.append(
            Finding(
                rule_id="APD104",
                title="Instruction authority changed with permission expansion",
                severity=Severity.HIGH,
                summary=(
                    "Agent instructions changed in the same PR as tool, runner, deploy, "
                    "or egress reach."
                ),
                evidence=_evidence(involved),
                changes=involved,
                reviewer_decision=(
                    "Review whether the instruction change alters how the new permission is used."
                ),
            )
        )

    return findings


def _host_is_multi_tenant(host: str) -> bool:
    lowered = host.lower()
    return any(
        token in lowered
        for token in (
            "*.vercel.app",
            "githubusercontent.com",
            "gist.",
            "storage.googleapis.com",
            "hooks.slack.com",
            "box.com",
            "drive.google.com",
        )
    )


def _evidence(changes: list[PermissionChange]) -> list[str]:
    return [change.atom.evidence for change in changes if change.atom.evidence]


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.summary,
            tuple(sorted(change.atom.path for change in finding.changes)),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return sorted(deduped, key=lambda item: (-item.severity, item.rule_id, item.title))
