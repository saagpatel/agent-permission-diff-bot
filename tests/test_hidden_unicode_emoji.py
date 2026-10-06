import pytest

from agent_permission_diff_bot.persistence import PAYLOAD_PATTERNS

HIDDEN = PAYLOAD_PATTERNS["hidden_unicode"]


@pytest.mark.parametrize(
    "text",
    [
        "⚠️ Do not push to main",
        "family \U0001f468‍\U0001f469‍\U0001f467",
        "✅️ done",
        "keycap 1️⃣",
        "flag \U0001f3f3️‍\U0001f308",
    ],
)
def test_emoji_sequences_are_not_hidden_unicode(text: str) -> None:
    assert HIDDEN.search(text) is None


@pytest.mark.parametrize(
    "text",
    [
        "plain️text",
        "a‍b",
        "trailing‍",
        "tag\U000e0041smuggle",
        "zero​width",
        "bidi‮override",
        "selector\U000e0100",
    ],
)
def test_bare_invisible_characters_are_hidden_unicode(text: str) -> None:
    assert HIDDEN.search(text) is not None
