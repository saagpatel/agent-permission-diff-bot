from __future__ import annotations

import textwrap

import pytest

from agent_permission_diff_bot.checks.swallowed import (
    ChangedFile,
    added_lines_between,
    added_lines_from_patch,
    scan_swallowed,
)
from agent_permission_diff_bot.model import Severity


def new_file(path: str, source: str) -> ChangedFile:
    text = textwrap.dedent(source).lstrip("\n")
    return ChangedFile(path=path, text=text, added=added_lines_between("", text))


def scan(path: str, source: str) -> list[tuple[str, int | None, Severity]]:
    result = scan_swallowed([new_file(path, source)])
    return [(f.rule_id, f.line, f.severity) for f in result.findings]


@pytest.mark.parametrize(
    "body",
    ["pass", "...", "return None", "return False", "return []", "result = None", "continue"],
)
def test_python_silent_handlers_are_found(body: str) -> None:
    source = f"""
    for item in items:
        try:
            item.save()
        except Exception:
            {body}
    """
    assert scan("app/x.py", source) == [("SW-data-loss", 4, Severity.HIGH)]


@pytest.mark.parametrize(
    "body",
    [
        "raise",
        "raise RuntimeError('save failed') from err",
        "log.exception('save failed')",
        "errors.append(err)",
        "return err",
    ],
)
def test_python_handlers_that_keep_the_error_are_not_found(body: str) -> None:
    source = f"""
    def f(item, log, errors):
        try:
            item.save()
        except Exception as err:
            {body}
    """
    assert scan("app/x.py", source) == []


def test_ranking_puts_auth_before_data_before_network_before_other() -> None:
    source = """
    def f():
        try:
            parse(blob)
        except ValueError:
            pass
        try:
            requests.post(url)
        except Exception:
            pass
        try:
            db.commit()
        except Exception:
            pass
        try:
            verify_token(token)
        except Exception:
            pass
    """
    assert [r[0] for r in scan("app/x.py", source)] == [
        "SW-auth",
        "SW-data-loss",
        "SW-network",
        "SW-other",
    ]


def test_bare_except_notes_it_swallows_exit() -> None:
    result = scan_swallowed([new_file("x.py", "try:\n    run()\nexcept:\n    pass\n")])
    [finding] = result.findings
    assert finding.title == "`bare except` dropped"
    assert finding.severity == Severity.MEDIUM
    assert any("sys.exit()" in line for line in finding.allows)


def test_narrow_benign_type_is_low_and_says_so_honestly() -> None:
    source = "try:\n    os.stat(p)\nexcept FileNotFoundError:\n    pass\n"
    [finding] = scan_swallowed([new_file("x.py", source)]).findings
    assert finding.severity == Severity.LOW
    assert finding.allows[0].startswith("Probably deliberate")


def test_contextlib_suppress_is_found() -> None:
    source = "with contextlib.suppress(Exception):\n    shutil.rmtree(tmp)\n"
    [finding] = scan_swallowed([new_file("x.py", source)]).findings
    assert finding.title == "`suppress(Exception)` dropped around a write"


def test_deliberate_marker_lists_the_catch_with_its_reason_and_does_not_rank_it() -> None:
    source = (
        "try:\n    os.remove(p)\nexcept OSError:  # swallowed: ok - best effort cleanup\n    pass\n"
    )
    result = scan_swallowed([new_file("x.py", source)])
    assert result.findings == []
    [catch] = result.deliberate
    assert (catch.line, catch.reason) == (3, "best effort cleanup")


def test_noqa_suppression_counts_as_deliberate_without_a_reason() -> None:
    source = "try:\n    os.remove(p)\nexcept Exception:  # noqa: S110\n    pass\n"
    result = scan_swallowed([new_file("x.py", source)])
    assert result.findings == []
    assert "no reason given" in result.deliberate[0].reason


def test_only_handlers_the_diff_touches_are_reported() -> None:
    base = "try:\n    a()\nexcept Exception:\n    pass\n"
    head = base + "\ntry:\n    b.save()\nexcept Exception:\n    pass\n"
    changed = ChangedFile("x.py", head, added_lines_between(base, head))
    assert [f.line for f in scan_swallowed([changed]).findings] == [8]


def test_raise_turned_into_pass_is_reported() -> None:
    base = "try:\n    db.commit()\nexcept Exception:\n    raise\n"
    head = "try:\n    db.commit()\nexcept Exception:\n    pass\n"
    changed = ChangedFile("x.py", head, added_lines_between(base, head))
    assert [f.rule_id for f in scan_swallowed([changed]).findings] == ["SW-data-loss"]


def test_unparseable_python_leaves_a_note() -> None:
    result = scan_swallowed([new_file("x.py", "def broken(:\n")])
    assert result.findings == []
    assert "did not parse" in result.notes[0]


def test_typescript_empty_catch_and_promise_catch() -> None:
    source = """
    export async function load(id: string) {
      try {
        const res = await fetch(`/api/${id}`);
        return res.json();
      } catch (e) {}
    }
    export async function save(db: Db, row: Row) {
      await db.rows.upsert(row).catch(() => {});
      await db.rows.delete(row).catch(() => null);
    }
    """
    assert scan("web/api.ts", source) == [
        ("SW-data-loss", 8, Severity.HIGH),
        ("SW-data-loss", 9, Severity.HIGH),
        ("SW-network", 5, Severity.MEDIUM),
    ]


@pytest.mark.parametrize(
    "handler",
    [
        "catch (e) { console.error(e) }",
        "catch (e) { throw new Error('wrapped', { cause: e }) }",
        "catch (err) { return err }",
    ],
)
def test_typescript_catches_that_keep_the_error_are_not_found(handler: str) -> None:
    assert scan("web/x.ts", f"try {{ verifyToken(t) }} {handler}\n") == []


def test_typescript_promise_catch_that_logs_is_not_found() -> None:
    assert scan("web/x.ts", "fetch(url).catch((e) => console.warn(e));\n") == []


def test_tsx_and_deliberate_marker() -> None:
    source = """
    export function Widget() {
      try { track('view') } catch {
        // swallowed: ok analytics must never break the page
      }
      return <div />;
    }
    """
    result = scan_swallowed([new_file("web/Widget.tsx", source)])
    assert result.findings == []
    assert result.deliberate[0].reason == "analytics must never break the page"


def test_auth_check_in_typescript_is_high() -> None:
    assert scan("web/auth.ts", "try { verifyToken(t) } catch { return null }\n") == [
        ("SW-auth", 1, Severity.HIGH)
    ]


def test_other_languages_are_ignored() -> None:
    assert scan("main.go", "func f() {}\n") == []


def test_added_lines_from_github_patch() -> None:
    patch = "@@ -1,3 +1,4 @@\n a\n-b\n+B\n+C\n d\n@@ -10,2 +11,3 @@\n x\n+y\n z"
    assert added_lines_from_patch(patch) == {2, 3, 12}


def test_added_lines_for_new_file_patch() -> None:
    assert added_lines_from_patch("@@ -0,0 +1,2 @@\n+one\n+two") == {1, 2}


def test_removed_line_that_looks_like_a_header_does_not_shift_lines() -> None:
    assert added_lines_from_patch("@@ -1,3 +1,3 @@\n a\n----------\n+b\n c\n+x") == {2, 4}


@pytest.mark.parametrize(
    "handler",
    [
        "catch (e) { ok = false; }",
        "catch (e) { this.failed = true; }",
        "catch { return -1; }",
        "catch (e) { return void 0 }",
    ],
)
def test_typescript_flag_assignments_and_unary_constants_swallow(handler: str) -> None:
    assert [r[0] for r in scan("web/x.ts", f"try {{ await verifyToken(t) }} {handler}\n")] == [
        "SW-auth"
    ]


def test_typescript_assigning_the_error_keeps_it() -> None:
    assert scan("web/x.ts", "try { save() } catch (e) { lastError = e; }\n") == []


def test_python_negative_constant_return_swallows() -> None:
    source = (
        "def f():\n    try:\n        verify_token(t)\n    except Exception:\n        return -1\n"
    )
    assert [r[0] for r in scan("x.py", source)] == ["SW-auth"]
