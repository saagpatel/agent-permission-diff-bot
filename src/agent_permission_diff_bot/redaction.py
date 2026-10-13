from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_NAME = re.compile(
    r"(?:access.?token|token|secret|password|passwd|credential|(?:api.?|private.?)?key|"
    r"authorization|auth|sig(?:nature)?)",
    re.I,
)


def redact_text(value: str) -> str:
    value = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1[REDACTED]@", value)
    value = re.sub(
        r"(?i)(--?(?:access[-_]?token|token|password|passwd|secret|credential|private[-_]?key|"
        r"client[-_]?secret|api[-_]?key|auth|bearer)(?:=|\s+|,))([^\s,]+)",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)=([^\s,;]+)",
        r"\1=[REDACTED]",
        value,
    )
    return re.sub(r"https?://[^\s`]+", lambda match: redact_url(match.group(0)), value)


def redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        query = urlencode(
            [
                (key, "[REDACTED]" if _SECRET_NAME.search(key) else item)
                for key, item in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
        return urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))
    except ValueError:
        return "[REDACTED URL]"
