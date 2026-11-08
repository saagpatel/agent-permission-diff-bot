from __future__ import annotations

import sys
import textwrap

import pytest

from agent_permission_diff_bot.checks.swallowed import (
    ChangedFile,
    changed_lines_between,
    changed_lines_from_patch,
    scan_swallowed,
)
from agent_permission_diff_bot.model import Severity


def new_file(path: str, source: str) -> ChangedFile:
    text = textwrap.dedent(source).lstrip("\n")
    return ChangedFile(path=path, text=text, changed=changed_lines_between("", text))


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
    changed = ChangedFile("x.py", head, changed_lines_between(base, head))
    assert [f.line for f in scan_swallowed([changed]).findings] == [8]


def test_raise_turned_into_pass_is_reported() -> None:
    base = "try:\n    db.commit()\nexcept Exception:\n    raise\n"
    head = "try:\n    db.commit()\nexcept Exception:\n    pass\n"
    changed = ChangedFile("x.py", head, changed_lines_between(base, head))
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
    # Lines 2-3 are added; line 1 sits before the deleted `b`, so it is touched too.
    assert changed_lines_from_patch(patch) == {1, 2, 3, 12}


def test_added_lines_for_new_file_patch() -> None:
    assert changed_lines_from_patch("@@ -0,0 +1,2 @@\n+one\n+two") == {1, 2}


def test_removed_line_that_looks_like_a_header_does_not_shift_lines() -> None:
    assert changed_lines_from_patch("@@ -1,3 +1,3 @@\n a\n----------\n+b\n c\n+x") == {1, 2, 4}


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


def test_a_handler_silenced_only_by_deleting_a_line_is_reported() -> None:
    base = "try:\n    db.commit()\nexcept Exception:\n    logger.exception('failed')\n    pass\n"
    head = "try:\n    db.commit()\nexcept Exception:\n    pass\n"
    changed = ChangedFile("x.py", head, changed_lines_between(base, head))
    assert [f.rule_id for f in scan_swallowed([changed]).findings] == ["SW-data-loss"]


def test_deletion_in_a_github_patch_touches_the_handler() -> None:
    head = "try:\n    db.commit()\nexcept Exception:\n    pass\n"
    patch = "@@ -3,3 +3,2 @@\n except Exception:\n-    logger.exception('failed')\n     pass"
    changed = ChangedFile("x.py", head, changed_lines_from_patch(patch))
    assert [f.rule_id for f in scan_swallowed([changed]).findings] == ["SW-data-loss"]


def test_a_marker_inside_a_string_is_not_a_deliberate_mark() -> None:
    source = (
        "try:\n    verify_token(t)\nexcept Exception:\n    result = 'swallowed: ok just data'\n"
    )
    result = scan_swallowed([new_file("x.py", source)])
    assert result.deliberate == []
    assert [f.rule_id for f in result.findings] == ["SW-auth"]


def test_a_typescript_marker_inside_a_string_is_not_a_deliberate_mark() -> None:
    source = "try { verifyToken(t) } catch { const note = 'swallowed: ok data'; }\n"
    result = scan_swallowed([new_file("web/x.ts", source)])
    assert result.deliberate == []


def test_trailing_comment_on_a_promise_catch_still_marks_it() -> None:
    source = "fetch(url).catch(() => {}); // swallowed: ok prefetch is optional\n"
    result = scan_swallowed([new_file("web/x.ts", source)])
    assert result.findings == []
    assert result.deliberate[0].reason == "prefetch is optional"


def test_promise_catch_that_only_sets_a_flag_swallows() -> None:
    assert [r[0] for r in scan("web/x.ts", "fetch(url).catch(() => { ok = false; });\n")] == [
        "SW-network"
    ]


def test_promise_catch_that_stores_the_error_keeps_it() -> None:
    assert scan("web/x.ts", "fetch(url).catch((e) => { lastError = e; });\n") == []


@pytest.mark.parametrize(
    "handler", ["(e) => { recordError(e).acknowledged = true; }", "(e) => { e.seen = true; }"]
)
def test_promise_catch_whose_target_uses_the_error_keeps_it(handler: str) -> None:
    assert scan("web/x.ts", f"fetch(url).catch({handler});\n") == []


def test_promise_catch_that_sets_a_member_flag_swallows() -> None:
    found = scan("web/x.ts", "fetch(url).catch(() => { this.state.failed = true; });\n")
    assert [r[0] for r in found] == ["SW-network"]


@pytest.mark.parametrize(
    "source",
    [
        "try { f(); } catch (e) { failed[key] = true; }\n",
        "fetch(url).catch(() => { failed[key] = true; });\n",
    ],
)
def test_a_subscript_flag_assignment_swallows_in_both_catch_forms(source: str) -> None:
    assert len(scan("web/x.ts", source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "try { f(); } catch (e) { failed[e.code] = true; }\n",
        "fetch(url).catch((e) => { failed[e] = true; });\n",
    ],
)
def test_a_subscript_keyed_by_the_error_keeps_it(source: str) -> None:
    assert scan("web/x.ts", source) == []


@pytest.mark.parametrize(
    "target",
    ["this.#failed", "state!.failed", "(this as any).failed", "(state satisfies S).failed"],
)
def test_wrapped_and_private_flag_targets_still_swallow(target: str) -> None:
    handler = f"try {{ f(); }} catch (e) {{ {target} = true; }}"
    source = f"class A {{ #failed = false; m() {{ {handler} }} }}\n"
    assert len(scan("web/x.ts", source)) == 1


@pytest.mark.skipif(sys.version_info < (3, 12), reason="3.11 gives the overflow no message")
def test_python_nested_too_deeply_to_parse_is_refused_not_unfinished() -> None:
    from agent_permission_diff_bot.checks.swallowed import ChangedFile, scan_swallowed

    text = "x = " + "-" * 200_000 + "1\ntry:\n    a()\nexcept Exception:\n    pass\n"
    result = scan_swallowed([ChangedFile("deep.py", text, frozenset(range(1, 6)))])
    assert not result.crashed and result.findings == []
    assert any("not scanned" in note for note in result.notes)


@pytest.mark.parametrize(
    "source",
    [
        "p.catch(() => (failed = true));\n",
        "p.catch(() => failed = true);\n",
        "try { f(); } catch (e) { failed ||= true; }\n",
        "try { f(); } catch (e) { errors += 1; }\n",
        "try { f(); } catch (e) { errors++; }\n",
    ],
)
def test_expression_body_and_compound_flag_sets_swallow(source: str) -> None:
    assert len(scan("web/x.ts", source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "try { f(); } catch ({ message }) { last = message; }\n",
        "try { f(); } catch (e) { counts[e.code]++; }\n",
        "p.catch((e) => (last = e));\n",
    ],
)
def test_a_flag_set_that_uses_the_error_keeps_it(source: str) -> None:
    assert scan("web/x.ts", source) == []
