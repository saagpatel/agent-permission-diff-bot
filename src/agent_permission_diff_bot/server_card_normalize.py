from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agent_permission_diff_bot.server_card_model import (
    CURRENT_REGISTRY_SCHEMA,
    ContractFamily,
    NormalizedField,
    NormalizedServerCard,
    RawServerCard,
    SourceSnapshot,
)

KNOWN_REGISTRY_SCHEMA_MARKERS = (
    "2025-12-11/server.schema.json",
    "2025-10-17/server.schema.json",
    "docs/reference/server-json/draft/server.schema.json",
)
STANDARD_SERVER_KEYS = {
    "$schema",
    "name",
    "title",
    "description",
    "repository",
    "version",
    "websiteUrl",
    "icons",
    "packages",
    "remotes",
    "_meta",
}
VENDOR_FAMILIES = {
    "auth",
    "authentication",
    "securitySchemes",
    "security_schemes",
    "capabilities",
    "compatibility",
    "protocolVersions",
    "supportedVersions",
    "endpoints",
    "deployment",
    "transports",
}
SENSITIVE_RE = re.compile(
    r"(?:secret|password|passwd|token|credential|private.?key|api.?key|authorization)",
    re.IGNORECASE,
)


class _FieldBuilder:
    def __init__(self) -> None:
        self.fields: dict[str, NormalizedField] = {}

    def add(
        self,
        path: str,
        value: Any,
        *,
        category: str,
        contract: str,
        standard: bool,
        confidence: str = "high",
        sensitive: bool = False,
        display_value: bool = True,
    ) -> None:
        normalized = _canonical_value(value)
        fingerprint = _fingerprint(normalized)
        is_sensitive = sensitive or _path_is_sensitive(path)
        if is_sensitive:
            display = "[REDACTED]"
        elif display_value:
            display = _display(normalized)
        else:
            display = f"<{_value_type(normalized)} sha256:{fingerprint[:12]}>"
        self.fields[path] = NormalizedField(
            path=path,
            category=category,
            state="present",
            value=normalized,
            display=display,
            fingerprint=fingerprint,
            contract=contract,
            standard=standard,
            confidence=confidence,
            sensitive=is_sensitive,
        )

    def values(self) -> tuple[NormalizedField, ...]:
        return tuple(self.fields[path] for path in sorted(self.fields))


def normalize_snapshot(snapshot: SourceSnapshot) -> tuple[NormalizedServerCard, ...]:
    return tuple(normalize_card(card) for card in snapshot.cards)


def normalize_card(raw: RawServerCard) -> NormalizedServerCard:
    try:
        payload = json.loads(raw.text)
    except json.JSONDecodeError as exc:
        return NormalizedServerCard(
            key=raw.provenance.path,
            provenance=raw.provenance,
            contract_family="malformed",
            schema_uri=None,
            schema_status="invalid",
            validity="invalid",
            fields=(),
            issues=(f"JSON parse error at line {exc.lineno}, column {exc.colno}",),
        )
    if not isinstance(payload, dict):
        return NormalizedServerCard(
            key=raw.provenance.path,
            provenance=raw.provenance,
            contract_family="malformed",
            schema_uri=None,
            schema_status="invalid",
            validity="invalid",
            fields=(),
            issues=("Top-level server card must be a JSON object",),
        )

    builder = _FieldBuilder()
    issues: list[str] = []
    family = _contract_family(payload)
    card_payload = payload
    wrapper_meta: Any = None
    if family == "mcp_registry_api":
        card_payload = payload["server"]
        wrapper_meta = payload.get("_meta")
    elif family == "mcp_protocol_discovery":
        card_payload = payload.get("result", payload)

    schema_uri = card_payload.get("$schema") if isinstance(card_payload, dict) else None
    schema_status = _schema_status(schema_uri, family)

    if family in {"mcp_registry_server_json", "mcp_registry_api"}:
        _normalize_server_json(builder, card_payload, issues)
        if wrapper_meta is not None:
            _normalize_registry_meta(builder, wrapper_meta, issues)
    elif family == "mcp_protocol_discovery":
        _normalize_protocol_discovery(builder, card_payload, issues)
    else:
        _normalize_vendor_card(builder, card_payload, issues)

    if schema_status == "unknown":
        issues.append(f"Unrecognized declared schema URI: {schema_uri}")
    if family in {"mcp_registry_server_json", "mcp_registry_api"}:
        for required in ("name", "description", "version"):
            if not isinstance(card_payload.get(required), str) or not card_payload.get(required):
                issues.append(f"Required Registry field is missing or invalid: {required}")
    validity: Literal["valid", "partial", "invalid"] = "valid" if not issues else "partial"
    key = _card_key(card_payload, raw.provenance.path, family)
    return NormalizedServerCard(
        key=key,
        provenance=raw.provenance,
        contract_family=family,
        schema_uri=schema_uri if isinstance(schema_uri, str) else None,
        schema_status=schema_status,
        validity=validity,
        fields=builder.values(),
        issues=tuple(sorted(set(issues))),
    )


def missing_field_state(card: NormalizedServerCard) -> str:
    if card.validity == "invalid" or card.schema_status == "unknown":
        return "unknown"
    return "absent"


def _contract_family(payload: dict[str, Any]) -> ContractFamily:
    if isinstance(payload.get("server"), dict):
        return "mcp_registry_api"
    candidate = payload.get("result", payload)
    if isinstance(candidate, dict) and (
        "supportedVersions" in candidate
        or (
            "capabilities" in candidate
            and (
                "_meta" in candidate
                or "io.modelcontextprotocol/serverInfo" in candidate
                or "ttlMs" in candidate
            )
        )
    ):
        return "mcp_protocol_discovery"
    if "$schema" in payload or all(key in payload for key in ("name", "description", "version")):
        return "mcp_registry_server_json"
    return "vendor_server_card"


def _schema_status(
    schema_uri: Any, family: str
) -> Literal["recognized", "absent", "unknown", "invalid"]:
    if family == "mcp_protocol_discovery":
        return "recognized"
    if schema_uri is None:
        return "absent"
    if not isinstance(schema_uri, str):
        return "invalid"
    if schema_uri == CURRENT_REGISTRY_SCHEMA or any(
        marker in schema_uri for marker in KNOWN_REGISTRY_SCHEMA_MARKERS
    ):
        return "recognized"
    return "unknown"


def _normalize_server_json(builder: _FieldBuilder, card: dict[str, Any], issues: list[str]) -> None:
    contract = "mcp_registry_server_json"
    scalar_fields = {
        "$schema": ("schema.uri", "schema"),
        "name": ("identity.name", "identity"),
        "title": ("identity.title", "identity"),
        "description": ("identity.description", "identity"),
        "version": ("identity.version", "version"),
        "websiteUrl": ("identity.website_url", "identity"),
    }
    for source, (path, category) in scalar_fields.items():
        if source in card:
            builder.add(
                path,
                card[source],
                category=category,
                contract=contract,
                standard=True,
            )

    repository = card.get("repository")
    if repository is not None:
        if isinstance(repository, dict):
            for key, path in {
                "url": "repository.url",
                "source": "repository.source",
                "id": "repository.id",
                "subfolder": "repository.subfolder",
            }.items():
                if key in repository:
                    builder.add(
                        path,
                        repository[key],
                        category="package_provenance",
                        contract=contract,
                        standard=True,
                    )
            _unknown_mapping_fields(
                builder,
                repository,
                {"url", "source", "id", "subfolder"},
                prefix="extensions.repository",
            )
        else:
            issues.append("Registry field repository must be an object")

    _normalize_packages(builder, card.get("packages"), issues)
    _normalize_remotes(builder, card.get("remotes"), issues)

    icons = card.get("icons")
    if icons is not None:
        if isinstance(icons, list):
            icon_shapes = tuple(sorted(_fingerprint(_canonical_value(item)) for item in icons))
            builder.add(
                "identity.icons",
                icon_shapes,
                category="identity",
                contract=contract,
                standard=True,
                display_value=False,
            )
        else:
            issues.append("Registry field icons must be an array")

    meta = card.get("_meta")
    if meta is not None:
        _flatten_extension(builder, meta, "extensions._meta", contract="registry_extension")

    for key in sorted(set(card) - STANDARD_SERVER_KEYS):
        _flatten_extension(builder, card[key], f"extensions.{key}")


def _normalize_packages(builder: _FieldBuilder, packages: Any, issues: list[str]) -> None:
    if packages is None:
        return
    if not isinstance(packages, list):
        issues.append("Registry field packages must be an array")
        return
    identities: list[str] = []
    transports: list[str] = []
    endpoints: list[str] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            issues.append(f"Package entry {index} must be an object")
            continue
        registry_key = "registryType" if "registryType" in package else "registry_type"
        registry_type = str(package.get(registry_key, "UNKNOWN"))
        identifier = str(package.get("identifier", "UNKNOWN"))
        item_key = _item_key(registry_type, identifier)
        identities.append(f"{registry_type}:{identifier}")
        standard_registry = registry_key == "registryType"
        builder.add(
            f"packages[{item_key}].registry_type",
            registry_type,
            category="package_provenance",
            contract=(
                "mcp_registry_server_json" if standard_registry else "vendor_alias:registry_type"
            ),
            standard=standard_registry,
            confidence="high" if standard_registry else "medium",
        )
        for key, suffix in {
            "identifier": "identifier",
            "version": "version",
            "registryBaseUrl": "registry_base_url",
            "fileSha256": "file_sha256",
            "runtimeHint": "runtime_hint",
        }.items():
            if key in package:
                builder.add(
                    f"packages[{item_key}].{suffix}",
                    package[key],
                    category="package_provenance",
                    contract="mcp_registry_server_json",
                    standard=True,
                    sensitive=key == "fileSha256",
                )
        transport = package.get("transport")
        if isinstance(transport, dict):
            transport_type = str(transport.get("type", "UNKNOWN"))
            transports.append(transport_type)
            if isinstance(transport.get("url"), str):
                endpoints.append(transport["url"])
            _normalize_transport(builder, transport, f"packages[{item_key}].transport")
        elif transport is not None:
            issues.append(f"Package {item_key} transport must be an object")
        _normalize_inputs(
            builder,
            package.get("environmentVariables"),
            f"packages[{item_key}].environment",
            issues,
        )
        for argument_key in ("runtimeArguments", "packageArguments"):
            if argument_key in package:
                builder.add(
                    f"packages[{item_key}].{argument_key}",
                    package[argument_key],
                    category="package_provenance",
                    contract="mcp_registry_server_json",
                    standard=True,
                    display_value=False,
                )
        known = {
            "registryType",
            "registry_type",
            "registryBaseUrl",
            "identifier",
            "version",
            "fileSha256",
            "runtimeHint",
            "transport",
            "runtimeArguments",
            "packageArguments",
            "environmentVariables",
        }
        _unknown_mapping_fields(builder, package, known, prefix=f"extensions.packages[{item_key}]")
    builder.add(
        "packages.declared",
        tuple(sorted(identities)),
        category="package_provenance",
        contract="mcp_registry_server_json",
        standard=True,
        display_value=False,
    )
    if transports:
        builder.add(
            "transports.declared",
            tuple(sorted(set(transports))),
            category="transport",
            contract="mcp_registry_server_json",
            standard=True,
        )
    if endpoints:
        builder.add(
            "endpoints.declared",
            tuple(sorted(set(endpoints))),
            category="endpoint",
            contract="mcp_registry_server_json",
            standard=True,
        )


def _normalize_remotes(builder: _FieldBuilder, remotes: Any, issues: list[str]) -> None:
    if remotes is None:
        return
    if not isinstance(remotes, list):
        issues.append("Registry field remotes must be an array")
        return
    transports: list[str] = []
    endpoints: list[str] = []
    for index, remote in enumerate(remotes):
        if not isinstance(remote, dict):
            issues.append(f"Remote entry {index} must be an object")
            continue
        transport_type = str(remote.get("type", "UNKNOWN"))
        url = str(remote.get("url", "UNKNOWN"))
        item_key = _item_key(transport_type, url)
        transports.append(transport_type)
        endpoints.append(url)
        _normalize_transport(builder, remote, f"remotes[{item_key}]")
        _unknown_mapping_fields(
            builder,
            remote,
            {"type", "url", "headers", "variables"},
            prefix=f"extensions.remotes[{item_key}]",
        )
    builder.add(
        "remotes.declared",
        tuple(
            sorted(
                f"{item.get('type', 'UNKNOWN')}:{item.get('url', 'UNKNOWN')}"
                for item in remotes
                if isinstance(item, dict)
            )
        ),
        category="endpoint",
        contract="mcp_registry_server_json",
        standard=True,
        display_value=False,
    )
    if transports:
        existing = builder.fields.get("transports.declared")
        values = set(existing.value if existing else ()) | set(transports)
        builder.add(
            "transports.declared",
            tuple(sorted(values)),
            category="transport",
            contract="mcp_registry_server_json",
            standard=True,
        )
    if endpoints:
        existing = builder.fields.get("endpoints.declared")
        values = set(existing.value if existing else ()) | set(endpoints)
        builder.add(
            "endpoints.declared",
            tuple(sorted(values)),
            category="endpoint",
            contract="mcp_registry_server_json",
            standard=True,
        )


def _normalize_transport(builder: _FieldBuilder, transport: dict[str, Any], prefix: str) -> None:
    for key, suffix, category in (
        ("type", "type", "transport"),
        ("url", "url", "endpoint"),
    ):
        if key in transport:
            builder.add(
                f"{prefix}.{suffix}",
                transport[key],
                category=category,
                contract="mcp_registry_server_json",
                standard=True,
            )
    _normalize_inputs(builder, transport.get("headers"), f"{prefix}.headers", [])
    variables = transport.get("variables")
    if isinstance(variables, dict):
        for name, value in sorted(variables.items()):
            if isinstance(value, dict):
                _normalize_input(builder, value, f"{prefix}.variables[{name}]", name=name)


def _normalize_inputs(builder: _FieldBuilder, inputs: Any, prefix: str, issues: list[str]) -> None:
    if inputs is None:
        return
    if not isinstance(inputs, list):
        issues.append(f"{prefix} must be an array")
        return
    names: list[str] = []
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            issues.append(f"{prefix} entry {index} must be an object")
            continue
        name = str(item.get("name", f"index-{index}"))
        names.append(name)
        _normalize_input(builder, item, f"{prefix}[{name}]", name=name)
    builder.add(
        f"{prefix}.declared",
        tuple(sorted(names)),
        category="authentication"
        if any(_looks_auth_name(name) for name in names)
        else "configuration",
        contract="mcp_registry_server_json",
        standard=True,
    )


def _normalize_input(
    builder: _FieldBuilder, item: dict[str, Any], prefix: str, *, name: str
) -> None:
    category = "authentication" if _looks_auth_name(name) else "configuration"
    for key, suffix in {
        "name": "name",
        "description": "description",
        "isRequired": "is_required",
        "format": "format",
        "isSecret": "is_secret",
        "default": "default",
        "placeholder": "placeholder",
        "choices": "choices",
        "value": "value",
    }.items():
        if key not in item:
            continue
        sensitive = key in {"value", "default"} and (
            bool(item.get("isSecret")) or _looks_auth_name(name)
        )
        builder.add(
            f"{prefix}.{suffix}",
            item[key],
            category=category,
            contract="mcp_registry_server_json",
            standard=True,
            sensitive=sensitive,
        )


def _normalize_registry_meta(builder: _FieldBuilder, meta: Any, issues: list[str]) -> None:
    if not isinstance(meta, dict):
        issues.append("Registry API _meta must be an object")
        return
    official = meta.get("io.modelcontextprotocol.registry/official")
    if isinstance(official, dict):
        for key in (
            "status",
            "statusMessage",
            "statusChangedAt",
            "publishedAt",
            "updatedAt",
            "isLatest",
        ):
            if key in official:
                builder.add(
                    f"registry.official.{key}",
                    official[key],
                    category="registry_metadata",
                    contract="mcp_registry_api_v0.1",
                    standard=True,
                )
    for key in sorted(set(meta) - {"io.modelcontextprotocol.registry/official"}):
        _flatten_extension(builder, meta[key], f"extensions.registry_meta.{key}")


def _normalize_protocol_discovery(
    builder: _FieldBuilder, result: dict[str, Any], issues: list[str]
) -> None:
    contract = "mcp_protocol_2026-07-28:server/discover"
    versions = result.get("supportedVersions")
    if versions is not None:
        if isinstance(versions, list):
            builder.add(
                "compatibility.supported_versions",
                tuple(sorted(str(item) for item in versions)),
                category="compatibility",
                contract=contract,
                standard=True,
            )
        else:
            issues.append("server/discover supportedVersions must be an array")
    capabilities = result.get("capabilities")
    if capabilities is not None:
        if isinstance(capabilities, dict):
            builder.add(
                "capabilities.declared",
                tuple(sorted(str(key) for key in capabilities)),
                category="capability",
                contract=contract,
                standard=True,
            )
            for key, value in sorted(capabilities.items()):
                _flatten_known_value(
                    builder,
                    value,
                    f"capabilities.{key}",
                    category="capability",
                    contract=contract,
                    standard=True,
                )
        else:
            issues.append("server/discover capabilities must be an object")
    meta = result.get("_meta")
    if isinstance(meta, dict):
        server_info = meta.get("io.modelcontextprotocol/serverInfo")
        if isinstance(server_info, dict):
            for key in ("name", "title", "version", "description", "websiteUrl"):
                if key in server_info:
                    builder.add(
                        f"runtime_declaration.server_info.{key}",
                        server_info[key],
                        category="identity" if key != "version" else "version",
                        contract="mcp_protocol_2026-07-28:ResultMetaObject",
                        standard=True,
                    )
    for key in sorted(
        set(result)
        - {"supportedVersions", "capabilities", "instructions", "_meta", "ttlMs", "cacheScope"}
    ):
        _flatten_extension(builder, result[key], f"extensions.protocol_result.{key}")


def _normalize_vendor_card(builder: _FieldBuilder, card: dict[str, Any], issues: list[str]) -> None:
    if not card:
        issues.append("Vendor server card is empty")
    for key, value in sorted(card.items()):
        _flatten_extension(builder, value, f"extensions.{key}")


def _flatten_extension(
    builder: _FieldBuilder,
    value: Any,
    path: str,
    *,
    contract: str = "vendor_extension",
) -> None:
    category = _extension_category(path)
    if isinstance(value, dict):
        if not value:
            builder.add(
                path,
                {},
                category=category,
                contract=contract,
                standard=False,
                confidence="medium",
                display_value=False,
            )
        for key, child in sorted(value.items()):
            _flatten_extension(builder, child, f"{path}.{key}", contract=contract)
        return
    if isinstance(value, list):
        if all(isinstance(item, (str, int, float, bool, type(None))) for item in value):
            builder.add(
                path,
                tuple(sorted((_canonical_value(item) for item in value), key=str)),
                category=category,
                contract=contract,
                standard=False,
                confidence="medium",
                display_value=False,
            )
        else:
            builder.add(
                path,
                value,
                category=category,
                contract=contract,
                standard=False,
                confidence="low",
                display_value=False,
            )
        return
    builder.add(
        path,
        value,
        category=category,
        contract=contract,
        standard=False,
        confidence="medium" if category != "extension" else "low",
        display_value=False,
    )


def _flatten_known_value(
    builder: _FieldBuilder,
    value: Any,
    path: str,
    *,
    category: str,
    contract: str,
    standard: bool,
) -> None:
    if isinstance(value, dict):
        if not value:
            builder.add(path, {}, category=category, contract=contract, standard=standard)
        for key, child in sorted(value.items()):
            _flatten_known_value(
                builder,
                child,
                f"{path}.{key}",
                category=category,
                contract=contract,
                standard=standard,
            )
    else:
        builder.add(path, value, category=category, contract=contract, standard=standard)


def _unknown_mapping_fields(
    builder: _FieldBuilder,
    mapping: dict[str, Any],
    known: set[str],
    *,
    prefix: str,
) -> None:
    for key in sorted(set(mapping) - known):
        _flatten_extension(builder, mapping[key], f"{prefix}.{key}")


def _card_key(card: dict[str, Any], path: str, family: str) -> str:
    if family == "mcp_protocol_discovery":
        meta = card.get("_meta")
        if isinstance(meta, dict):
            server_info = meta.get("io.modelcontextprotocol/serverInfo")
            if isinstance(server_info, dict) and isinstance(server_info.get("name"), str):
                return server_info["name"]
    name = card.get("name")
    return name if isinstance(name, str) and name else path


def _extension_category(path: str) -> str:
    lowered = path.lower()
    if any(token in lowered for token in ("auth", "securityscheme", "scope", "oauth")):
        return "authentication"
    if "capabilit" in lowered or "tool" in lowered or "resource" in lowered or "prompt" in lowered:
        return "capability"
    if any(token in lowered for token in ("compatib", "protocolversion", "supportedversion")):
        return "compatibility"
    if any(token in lowered for token in ("endpoint", "url", "host", "deployment")):
        return "endpoint"
    if "transport" in lowered:
        return "transport"
    if "package" in lowered or "registry" in lowered or "repository" in lowered:
        return "package_provenance"
    if "version" in lowered:
        return "version"
    if any(token in lowered for token in ("name", "title", "description")):
        return "identity"
    return "extension"


def _path_is_sensitive(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith(".is_secret") or lowered.endswith(".is_required"):
        return False
    if lowered.endswith(".name"):
        return False
    return bool(SENSITIVE_RE.search(path))


def _looks_auth_name(name: str) -> bool:
    return bool(SENSITIVE_RE.search(name))


def _item_key(*values: str) -> str:
    readable = ":".join(values)
    digest = hashlib.sha256(readable.encode("utf-8")).hexdigest()[:10]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", values[0]).strip("-")[:24]
    return f"{safe or 'item'}-{digest}"


def _canonical_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple, set)):
        items = [_canonical_value(item) for item in value]
        return tuple(sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str)))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _display(value: Any) -> str:
    if isinstance(value, tuple):
        return "[" + ", ".join(_display(item) for item in value) + "]"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return _redact_url(value)
    return str(value)


def _redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    userinfo = "[REDACTED]@" if parsed.username is not None else ""
    netloc = f"{userinfo}{hostname}{port}"
    query = urlencode(
        [(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def _value_type(value: Any) -> str:
    if isinstance(value, tuple):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def iter_field_paths(cards: Iterable[NormalizedServerCard]) -> tuple[str, ...]:
    return tuple(sorted({field.path for card in cards for field in card.fields}))
