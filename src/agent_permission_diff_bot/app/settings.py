"""GitHub App settings, read from the environment. Secrets are never logged or echoed."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from agent_permission_diff_bot.model import Severity

DEFAULT_API_URL = "https://api.github.com"


class SettingsError(ValueError):
    """A required setting is missing or invalid. The message names the setting, never a value."""


@dataclass(frozen=True)
class AppSettings:
    app_id: str
    private_key: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    api_url: str = DEFAULT_API_URL
    guard_fail_on: Severity | None = Severity.HIGH
    swallowed_fail_on: Severity | None = None
    analysis_timeout_s: float = 60.0
    analysis_memory_mb: int = 1024

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AppSettings:
        env = os.environ if env is None else env
        app_id = env.get("APDB_APP_ID", "").strip()
        if not app_id.isdigit():
            raise SettingsError("APDB_APP_ID must be the numeric GitHub App ID.")
        key_path = env.get("APDB_PRIVATE_KEY_PATH", "").strip()
        if not key_path:
            raise SettingsError("APDB_PRIVATE_KEY_PATH must point to the App's .pem private key.")
        try:
            private_key = Path(key_path).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise SettingsError(
                f"APDB_PRIVATE_KEY_PATH could not be read ({type(exc).__name__})."
            ) from exc
        if "PRIVATE KEY" not in private_key:
            raise SettingsError("APDB_PRIVATE_KEY_PATH does not contain a PEM private key.")
        secret = env.get("APDB_WEBHOOK_SECRET", "")
        if len(secret) < 16:
            raise SettingsError("APDB_WEBHOOK_SECRET must be set (at least 16 characters).")
        return cls(
            app_id=app_id,
            private_key=private_key,
            webhook_secret=secret,
            api_url=env.get("APDB_GITHUB_API_URL", DEFAULT_API_URL).rstrip("/"),
            guard_fail_on=parse_fail_on(env.get("APDB_GUARD_FAIL_ON", "high")),
            swallowed_fail_on=parse_fail_on(env.get("APDB_SWALLOWED_FAIL_ON", "never")),
            analysis_timeout_s=_positive(env, "APDB_ANALYSIS_TIMEOUT_S", 60.0),
            analysis_memory_mb=int(_positive(env, "APDB_ANALYSIS_MEMORY_MB", 1024)),
        )


def _positive(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SettingsError(f"{name} must be a positive number.") from exc
    if value <= 0:
        raise SettingsError(f"{name} must be a positive number.")
    return value


def parse_fail_on(value: str) -> Severity | None:
    """A severity name, or ``never`` for a check that only informs."""
    value = value.strip().lower()
    if value in {"never", "none", "off", ""}:
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise SettingsError("fail-on settings take critical, high, medium, low or never.") from exc
