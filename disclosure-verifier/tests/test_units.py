"""Unit tests for the deterministic parts of disclosure_verifier.

No LM Studio or Tomcat checkout required: CVSS math, JSON verdict extraction,
prompt truncation, edit application/revert, and disclosure parsing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from disclosure_verifier.cvss31 import (  # noqa: E402
    CvssError,
    base_score,
    extract_cvss_claim,
    parse_vector,
)
from disclosure_verifier.edits import apply_edits, backup, edits_from_adjudication, revert  # noqa: E402
from disclosure_verifier.jsonx import extract_json, parse_verdict  # noqa: E402
from disclosure_verifier.parse_disclosure import parse_disclosure, split_sections  # noqa: E402
from disclosure_verifier.prompts import (  # noqa: E402
    TruncationLog,
    build_adjudication_prompt,
    build_eval_prompt,
    truncate_middle,
)

# ---------------------------------------------------------------- CVSS 3.1


def test_parse_vector_full():
    v = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert v["AV"] == "N"
    assert v["S"] == "C"
    assert len(v) == 8


def test_parse_vector_rejects_bad_axis():
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:X/AC:L")
    with pytest.raises(CvssError):
        parse_vector("AV:N/AC:L")  # too few metrics


def test_known_scores():
    # Canonical examples from the CVSS 3.1 spec / calculator.
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert base_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N") == 4.2
    assert base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") == 5.5


def test_extract_cvss_claim():
    text = (
        "Severity: High. CVSS vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, "
        "base score 9.6."
    )
    vector, claimed = extract_cvss_claim(text)
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert claimed is not None and abs(claimed - 9.6) < 0.05


def test_extract_cvss_claim_none():
    assert extract_cvss_claim("no vector here") == (None, None)


# ---------------------------------------------------------------- jsonx


def test_extract_json_plain():
    obj = {"a": 1, "b": [1, 2]}
    assert extract_json(json.dumps(obj)) == obj


def test_extract_json_fenced_with_prose():
    raw = 'Sure! Here is the verdict:\n```json\n{"legit_security_finding": true}\n```\nHope that helps.'
    assert extract_json(raw) == {"legit_security_finding": True}


def test_extract_json_embedded_object():
    raw = 'prefix text {"x": {"y": "z with } brace"}} suffix'
    assert extract_json(raw) == {"x": {"y": "z with } brace"}}


def test_extract_json_trailing_commas():
    raw = '{"is_security_problem_per_trust_model": true, "cvss_assessment": {"base_score": 8.6,}, "impact": ["a",],}'
    assert extract_json(raw) == {
        "is_security_problem_per_trust_model": True,
        "cvss_assessment": {"base_score": 8.6},
        "impact": ["a"],
    }


def test_extract_json_trailing_comma_inside_string_preserved():
    raw = '{"note": "keep this comma, } intact", "x": 1,}'
    assert extract_json(raw) == {"note": "keep this comma, } intact", "x": 1}


def test_parse_verdict_missing_keys():
    verdict, problems = parse_verdict('{"a": 1}', ["a", "b"])
    assert verdict is not None
    assert any("b" in p for p in problems)


# ---------------------------------------------------------------- classification


def _enforce(verdict: dict):
    from disclosure_verifier.pipeline import _enforce_classification

    _enforce_classification(verdict)
    return verdict


def test_enforce_classification_security_issue():
    v = _enforce({"classification": "security_issue", "legit_security_finding": True})
    assert v["legit_security_finding"] is True


def test_enforce_classification_bug_coerces_legit_false():
    v = _enforce({"classification": "bug", "legit_security_finding": True})
    assert v["legit_security_finding"] is False
    assert "coerced" in v.get("classification_note", "")


def test_enforce_classification_hardening_not_legit():
    v = _enforce({"classification": "hardening", "legit_security_finding": False})
    assert v["legit_security_finding"] is False
    assert not v.get("classification_note")  # no coercion needed, no note


def test_enforce_classification_case_insensitive():
    v = _enforce({"classification": "  BUG ", "legit_security_finding": True})
    assert v["classification"] == "bug" and v["legit_security_finding"] is False


def test_enforce_classification_missing_coerces_from_legit_flag():
    v = _enforce({"legit_security_finding": True})
    assert v["classification"] == "security_issue"
    v2 = _enforce({})
    assert v2["classification"] == "bug" and v2["legit_security_finding"] is False


# ---------------------------------------------------------------- prompts


def test_truncate_middle_records_log():
    log = TruncationLog()
    text = "x" * 10_000
    out = truncate_middle(text, 1000, "section", log)
    assert len(out) <= 1000 + 64
    assert log.truncated
    assert log.entries[0]["omitted_chars"] > 0


def test_truncate_middle_noop_when_fits():
    log = TruncationLog()
    out = truncate_middle("short", 100, "s", log)
    assert out == "short" and not log.truncated


def _fake_bundle_text(n: int = 2000) -> str:
    return "# Test Disclosure\n\n" + ("body line\n" * n)


def test_eval_prompt_deterministic():
    bundle = _fake_bundle_text()
    mech = {"patch_applies_at_head": {"ok": True}}
    kwargs = dict(
        patch_text="--- a/x\n+++ b/x",
        test_sources=[("TestFoo.java", "class TestFoo {}")],
        mechanical_facts=mech,
        security_model_text="trust model text",
        input_char_budget=20_000,
    )
    m1, log1 = build_eval_prompt(bundle, **kwargs)
    m2, log2 = build_eval_prompt(bundle, **kwargs)
    assert m1 == m2
    assert json.dumps(log1.entries, sort_keys=True) == json.dumps(log2.entries, sort_keys=True)


def test_eval_prompt_truncates_large_input():
    bundle = _fake_bundle_text(50_000)  # ~600k chars
    mech = {"patch_applies_at_head": {"ok": True}}
    messages, log = build_eval_prompt(
        bundle,
        patch_text=None,
        test_sources=[],
        mechanical_facts=mech,
        security_model_text="sm",
        input_char_budget=10_000,
    )
    user = next(m["content"] for m in messages if m["role"] == "user")
    assert len(user) < 25_000  # budget + scaffold headroom
    assert log.truncated


def test_adjudication_prompt_contains_all_verdicts():
    bundle = _fake_bundle_text()
    va, vb, vc = (
        {"is_security_problem_per_trust_model": True},
        {"is_security_problem_per_trust_model": False},
        {"is_security_problem_per_trust_model": True},
    )
    messages, _ = build_adjudication_prompt(
        bundle,
        patch_text=None,
        test_sources=[],
        mechanical_facts={},
        verdicts=[
            ("A", "qwen/qwen3.8-27b", va),
            ("B", "vulnllm-r-7b", vb),
            ("C", "cyber-model-key", vc),
        ],
        security_model_text="sm",
        input_char_budget=20_000,
    )
    user = next(m["content"] for m in messages if m["role"] == "user")
    assert "EVALUATOR A VERDICT" in user and "EVALUATOR B VERDICT" in user
    assert "EVALUATOR C VERDICT" in user
    assert "qwen/qwen3.8-27b" in user and "vulnllm-r-7b" in user and "cyber-model-key" in user
    # dynamic model_agreement schema: one verdict key per evaluator + disagreements
    for letter in ("A", "B", "C"):
        assert f'"evaluator_{letter}_verdict"' in user
    assert '"disagreements"' in user


# ---------------------------------------------------------------- edits


def test_apply_and_revert_roundtrip(tmp_path: Path):
    f = tmp_path / "disclosure.md"
    original = "# Title\n\nold claim here\n"
    f.write_text(original, encoding="utf-8")

    class FakeBundle:
        path = f
        patch_file_path = None
        test_files = []

    verdict = {
        "edits": [
            {
                "target": "disclosure",
                "location": "body",
                "current_text": "old claim here",
                "proposed_text": "corrected claim",
                "reason": "accuracy",
            }
        ]
    }
    edits, notes = edits_from_adjudication(verdict, FakeBundle())
    assert not notes and len(edits) == 1

    result = apply_edits(edits)
    assert result.no_failures
    assert f.read_text(encoding="utf-8") == "# Title\n\ncorrected claim\n"
    assert (tmp_path / "disclosure.md.orig").exists()
    applied = result.applied[0]
    assert len(applied["sha256_before"]) == 64 and len(applied["sha256_after"]) == 64

    out = revert([f])
    assert out["restored"] == [str(f)] and not out["errors"]
    assert f.read_text(encoding="utf-8") == original


def test_apply_edit_missing_text_fails_cleanly(tmp_path: Path):
    f = tmp_path / "d.md"
    f.write_text("content", encoding="utf-8")

    class FakeBundle:
        path = f
        patch_file_path = None
        test_files = []

    edits, _ = edits_from_adjudication(
        {"edits": [{"target": "disclosure", "current_text": "absent", "proposed_text": "x"}]},
        FakeBundle(),
    )
    result = apply_edits(edits)
    assert not result.no_failures
    assert f.read_text(encoding="utf-8") == "content"  # untouched


def test_backup_keeps_first_original(tmp_path: Path):
    f = tmp_path / "d.md"
    f.write_text("v1", encoding="utf-8")
    backup(f)
    f.write_text("v2", encoding="utf-8")
    assert backup(f) is None  # already backed up
    assert (tmp_path / "d.md.orig").read_text(encoding="utf-8") == "v1"


# ---------------------------------------------------------------- parsing


def _write_disclosure(tmp_path: Path, name: str = "07-test-disclosure.md") -> Path:
    text = (
        "# Test Disclosure\n\n"
        "Commit: 9b2f4c6a8d1e3f5b7a9c0d2e4f6a8b0c1d3e5f7a\n"
        "CWE-20. Severity High, CVSS 3.1 vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, base score 9.6.\n\n"
        "## Root Cause\n\nSome text.\n\n"
        "Verification test: `test/webapp/org/apache/catalina/filters/TestFoo.java`\n\n"
        "```diff\n--- a/java/foo/Bar.java\n+++ b/java/foo/Bar.java\n@@ -1 +1 @@\n-old\n+new\n```\n"
    )
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_parse_disclosure_fields(tmp_path: Path):
    b = parse_disclosure(_write_disclosure(tmp_path), [tmp_path])
    assert b.slug == "07-test-disclosure"
    assert b.commit == "9b2f4c6a8d1e3f5b7a9c0d2e4f6a8b0c1d3e5f7a"
    assert b.cwe == "CWE-20"
    assert b.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert abs(b.claimed_score - 9.6) < 0.05
    assert b.diff_text is not None and b.diff_text.startswith("--- a/java/foo/Bar.java")
    assert "Root Cause" in b.sections


def test_parse_disclosure_resolves_test_file(tmp_path: Path):
    # Campaign-root layout: the root mirrors the repo (test/, tests/).
    tdir = tmp_path / "test" / "webapp" / "org" / "apache" / "catalina" / "filters"
    tdir.mkdir(parents=True)
    tf = tdir / "TestFoo.java"
    tf.write_text("class TestFoo {}", encoding="utf-8")

    b = parse_disclosure(_write_disclosure(tmp_path), [tmp_path])
    assert b.test_files == [tf.resolve()]
    assert b.unresolved_test_names == []


def test_parse_disclosure_resolves_bare_basename(tmp_path: Path):
    tdir = tmp_path / "test" / "org" / "apache" / "coyote"
    tdir.mkdir(parents=True)
    tf = tdir / "TestBare.java"
    tf.write_text("class TestBare {}", encoding="utf-8")

    p = tmp_path / "09-bare.md"
    p.write_text("# T\n\nVerification: `TestBare.java` fails before the fix.\n", encoding="utf-8")
    b = parse_disclosure(p, [tmp_path])
    assert b.test_files == [tf.resolve()]


def test_parse_disclosure_unresolved_test(tmp_path: Path):
    text = "# T\n\nSee TestMissing.java for details.\n"
    p = tmp_path / "08-x.md"
    p.write_text(text, encoding="utf-8")
    b = parse_disclosure(p, [tmp_path])
    assert b.test_files == []
    assert b.unresolved_test_names == ["TestMissing.java"]


def test_split_sections():
    secs = split_sections("# H1\nintro\n## A\nalpha\n## B\nbeta")
    assert set(secs) == {"A", "B"}
    assert secs["A"].strip() == "alpha"


# ---------------------------------------------------------------- config

VALID_CONFIG = """\
repo_root = "/tmp/tomcat"
disclosures_dir = "/tmp/campaign/disclosures"
security_model = "/tmp/campaign/SECURITY-MODEL.md"
jar_dir = "/tmp/libs"

[lmstudio]
url = "http://127.0.0.1:1234"

[generation]
seed = 1337
temperature = 0.0
top_p = 1.0
max_tokens_eval = 8192
max_tokens_final = 16384

[pipeline]
run_tests = true
postpatch = true

[[evaluators]]
name = "27b"
model_key = "qwen/qwen3.8-27b"
ctx_tokens = 65536
input_budget_chars = 140_000

[[evaluators]]
name = "7b"
model_key = "vulnllm-r-7b"
ctx_tokens = 32768
input_budget_chars = 80_000

[[evaluators]]
name = "cyber"
model_key = "cyber-model-key"
ctx_tokens = 98304
input_budget_chars = 140_000

[adjudicator]
model_key = "qwen/qwen3.8-27b"
ctx_tokens = 65536
input_budget_chars = 140_000
"""


def _write_config(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_config_full(tmp_path):
    from disclosure_verifier.config import load_config

    cfg = load_config(_write_config(tmp_path, VALID_CONFIG))
    assert cfg.repo_root == Path("/tmp/tomcat")
    assert cfg.disclosures_dir == Path("/tmp/campaign/disclosures")
    assert cfg.security_model == Path("/tmp/campaign/SECURITY-MODEL.md")
    assert cfg.jar_dir == Path("/tmp/libs")
    assert cfg.lmstudio_url == "http://127.0.0.1:1234"
    assert [e.name for e in cfg.evaluators] == ["27b", "7b", "cyber"]
    assert cfg.evaluators[1].model_key == "vulnllm-r-7b"
    assert cfg.evaluators[1].ctx_tokens == 32768
    assert cfg.adjudicator_model == "qwen/qwen3.8-27b"
    assert cfg.seed == 1337 and cfg.run_tests is True and cfg.postpatch is True


def test_load_config_missing_required_key(tmp_path):
    from disclosure_verifier.config import ConfigError, load_config

    text = VALID_CONFIG.replace('repo_root = "/tmp/tomcat"\n', "")
    with pytest.raises(ConfigError, match="repo_root"):
        load_config(_write_config(tmp_path, text))


def test_load_config_duplicate_evaluator_name(tmp_path):
    from disclosure_verifier.config import ConfigError, load_config

    text = VALID_CONFIG.replace('name = "cyber"', 'name = "27b"')
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(_write_config(tmp_path, text))


def test_load_config_bad_type(tmp_path):
    from disclosure_verifier.config import ConfigError, load_config

    text = VALID_CONFIG.replace("ctx_tokens = 32768", 'ctx_tokens = "32768"')
    with pytest.raises(ConfigError, match="integer"):
        load_config(_write_config(tmp_path, text))


def test_load_config_missing_file():
    from disclosure_verifier.config import ConfigError, load_config

    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/config.toml")


def test_select_evaluators_order_and_subset(tmp_path):
    from disclosure_verifier.config import load_config, select_evaluators

    cfg = load_config(_write_config(tmp_path, VALID_CONFIG))
    # All configured, in config-file order.
    assert [s.name for s in select_evaluators(cfg)] == ["27b", "7b", "cyber"]
    # Subset keeps config order regardless of request order; specs carry the values.
    subset = select_evaluators(cfg, ["cyber", "27b"])
    assert [s.name for s in subset] == ["27b", "cyber"]
    assert subset[0].model_key == "qwen/qwen3.8-27b" and subset[0].ctx_tokens == 65536


def test_select_evaluators_unknown_name(tmp_path):
    from disclosure_verifier.config import ConfigError, load_config, select_evaluators

    cfg = load_config(_write_config(tmp_path, VALID_CONFIG))
    with pytest.raises(ConfigError, match="unknown evaluator"):
        select_evaluators(cfg, ["nope"])
    with pytest.raises(ConfigError, match="no evaluators selected"):
        select_evaluators(cfg, [])


def test_apply_evaluator_overrides(tmp_path):
    from disclosure_verifier.config import (
        ConfigError,
        apply_evaluator_overrides,
        load_config,
    )

    cfg = load_config(_write_config(tmp_path, VALID_CONFIG))
    new_cfg = apply_evaluator_overrides(
        cfg, models={"7b": "other-7b"}, ctx_tokens={"cyber": 4096}
    )
    by_name = {e.name: e for e in new_cfg.evaluators}
    assert by_name["7b"].model_key == "other-7b"
    assert by_name["cyber"].ctx_tokens == 4096
    assert by_name["27b"] == cfg.evaluators[0]  # untouched
    with pytest.raises(ConfigError, match="unknown evaluator"):
        apply_evaluator_overrides(cfg, models={"nope": "x"})


def test_shipped_config_loads():
    """The committed config.toml at the tool root must always parse and validate."""
    from disclosure_verifier.config import load_config

    cfg = load_config()  # DEFAULT_CONFIG_PATH
    assert len(cfg.evaluators) >= 1
    assert all(e.model_key and e.ctx_tokens > 0 for e in cfg.evaluators)
    assert cfg.adjudicator_model and cfg.lmstudio_url
