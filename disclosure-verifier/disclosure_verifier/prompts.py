"""Deterministic prompt construction for the evaluation stages.

All prompts are built from fixed templates plus the disclosure bundle, so a
given (bundle, mechanical facts, budgets) input always yields byte-identical
prompts. Truncation is deterministic and recorded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# Rough chars-per-token estimate for mixed prose/code; used only to keep the
# prompt inside the model's context window with headroom for output.
CHARS_PER_TOKEN = 3.5


@dataclass
class TruncationLog:
    entries: list[dict] = field(default_factory=list)

    def record(self, section: str, original_chars: int, kept_chars: int, method: str) -> None:
        self.entries.append(
            {
                "section": section,
                "original_chars": original_chars,
                "kept_chars": kept_chars,
                "omitted_chars": original_chars - kept_chars,
                "method": method,
            }
        )

    @property
    def truncated(self) -> bool:
        return bool(self.entries)


def truncate_middle(text: str, limit: int, section: str, log: TruncationLog) -> str:
    """Deterministically shrink ``text`` to at most ``limit`` chars.

    Keeps the first 70% of the budget and the last 30%, joined by an explicit
    marker. Text already within the limit is returned unchanged.
    """
    if len(text) <= limit:
        return text
    head = max(1, int(limit * 0.7))
    tail = max(1, limit - head - 64)  # leave room for the marker itself
    omitted = len(text) - head - tail
    out = text[:head] + f"\n[...TRUNCATED: {omitted} chars omitted from {section}...]\n" + text[-tail:]
    log.record(section, len(text), len(out), "keep-head-70-tail-30")
    return out


def _fit_sections(
    parts: list[tuple[str, str]], budget: int, log: TruncationLog
) -> dict[str, str]:
    """Fit named sections into a total char budget.

    ``parts`` is ordered by priority (earlier = protected first). Each section
    gets its full text while the running total fits; once the budget is
    exhausted, remaining sections are truncated to their leftover share and
    any still-oversized one is cut further. The first section is never
    truncated below its own length unless it alone exceeds the whole budget.
    """
    result: dict[str, str] = {}
    remaining = budget
    for i, (name, text) in enumerate(parts):
        if len(text) <= remaining:
            result[name] = text
            remaining -= len(text)
            continue
        # This section must shrink; later sections get what is left after it.
        share = max(0, remaining - sum(len(t) for _, t in parts[i + 1 :]))
        if share <= 0:
            result[name] = ""
            log.record(name, len(text), 0, "dropped-no-budget")
            continue
        # Give this section the larger of its leftover share or a floor.
        limit = max(share, min(len(text), int(budget * 0.5)))
        if limit >= len(text):
            result[name] = text
            remaining -= len(text)
        else:
            result[name] = truncate_middle(text, limit, name, log)
            remaining -= len(result[name])
    return result


EVAL_SCHEMA = {
    "is_security_problem_per_trust_model": "boolean",
    "trust_model_analysis": "string - which trust-model rules apply and why the finding does or does not qualify (untrusted connector input? trusted exception? known non-finding?)",
    "reachability_assessment": "string - is the vulnerable path actually reachable by a client under stated preconditions?",
    "cvss_assessment": {
        "agrees_with_claimed_vector": "boolean",
        "proposed_vector": "string - CVSS 3.1 vector string (use the claimed one if you agree)",
        "base_score": "number - base score implied by proposed_vector",
        "rationale": "string - brief rationale for non-obvious axis choices",
    },
    "impact_assessment": "string - what the attacker concretely gains and what bounds it",
    "inaccuracies": [
        "list of strings - each a concrete, specific inaccuracy or weakness found in the disclosure text, its test(s), or its patch (empty list if none)"
    ],
    "confidence": "string - one of high / medium / low",
}

CLASSIFICATIONS = ("security_issue", "hardening", "bug", "invalid")

ADJUDICATION_SCHEMA = {
    "classification": (
        "string - REQUIRED, exactly one of: security_issue | hardening | bug | invalid. "
        "security_issue = a genuine vulnerability per the Tomcat trust model (legit_security_finding must be true). "
        "hardening = a real weakness worth fixing that is NOT a vulnerability under the trust model "
        "(e.g. requires unrealistic preconditions, or impact stays inside an already-trusted boundary). "
        "bug = a genuine functional defect in Tomcat that is demonstrated but not security-relevant. "
        "invalid = the disclosure's technical claim does not hold / the defect cannot be demonstrated."
    ),
    "legit_security_finding": "boolean - final ruling: is this a legitimate security finding per the Tomcat trust model? (must equal true iff classification == security_issue)",
    "confidence": "string - one of high / medium / low",
    "trust_model_ruling": "string - the decisive trust-model reasoning in 2-5 sentences",
    "final_cvss_vector": "string - CVSS 3.1 vector string you stand behind",
    "final_base_score": "number - base score implied by final_cvss_vector",
    "impact_summary": "string - concise statement of the real-world impact",
    # model_agreement is built dynamically per-evaluator in
    # build_adjudication_prompt (one *_verdict key per evaluator plus
    # "disagreements").
    "edits": [
        {
            "target": "string - one of: disclosure | test:<basename> | patch",
            "location": "string - short description of where in the artifact (section / line range / method)",
            "current_text": "string - exact text to replace (must appear verbatim in the artifact)",
            "proposed_text": "string - replacement text",
            "reason": "string - why this edit is necessary for accuracy",
        }
    ],
}


CVSS_NOTE = (
    "CVSS arithmetic is handled mechanically by the verifier: the mechanical facts include a "
    "computed base score for every CVSS 3.1 vector mentioned in the materials. Do NOT attempt to "
    "derive, verify, or recompute CVSS formulas from memory - use only the provided computed scores."
)

MUST_EMIT = (
    "You MUST write your JSON verdict as your final response text; never end your turn without "
    "writing it. If you have been deliberating, stop and write the JSON now."
)


def _schema_block(schema: dict) -> str:
    return json.dumps(schema, indent=2)


def build_eval_prompt(
    bundle_text: str,
    patch_text: str | None,
    test_sources: list[tuple[str, str]],
    mechanical_facts: dict,
    security_model_text: str,
    input_char_budget: int,
    log: TruncationLog | None = None,
) -> tuple[list[dict], TruncationLog]:
    """Build the stage-A/B evaluation messages.

    Returns (messages, truncation_log). ``test_sources`` is a list of
    (label, source_text) pairs in priority order.
    """
    log = log or TruncationLog()
    mech_json = json.dumps(mechanical_facts, indent=2, sort_keys=True)

    parts: list[tuple[str, str]] = [
        ("security_model", security_model_text),
        (f"disclosure:{bundle_slug(bundle_text)}", bundle_text),
        ("suggested_patch", patch_text or "(no embedded diff block found)"),
    ]
    for label, src in test_sources:
        parts.append((f"test_source:{label}", src))
    parts.append(("mechanical_facts", mech_json))

    # Reserve room for the fixed scaffolding (headers + task + schema).
    scaffold = 6000
    fitted = _fit_sections(parts, max(1000, input_char_budget - scaffold), log)

    user_parts: list[str] = []
    user_parts.append("=== SECURITY MODEL (Apache Tomcat trust model; the standard for triage) ===")
    user_parts.append(fitted.get("security_model", ""))
    slug_key = next(k for k in fitted if k.startswith("disclosure:"))
    user_parts.append("\n=== DISCLOSURE UNDER REVIEW (markdown, as written by the scanner) ===")
    user_parts.append(fitted.get(slug_key, ""))
    user_parts.append("\n=== SUGGESTED PATCH (unified diff embedded in the disclosure) ===")
    user_parts.append(fitted.get("suggested_patch", ""))
    for label, _src in test_sources:
        key = f"test_source:{label}"
        if key in fitted and fitted[key]:
            user_parts.append(f"\n=== VERIFICATION TEST SOURCE ({label}) ===")
            user_parts.append(fitted[key])
    user_parts.append("\n=== MECHANICAL FACTS (precomputed by the pipeline; treat as ground truth) ===")
    user_parts.append(fitted.get("mechanical_facts", mech_json))

    task = (
        "\n=== TASK ===\n"
        "You are an independent security reviewer for Apache Tomcat. Evaluate the disclosure above.\n"
        "1. Decide whether this is a genuine SECURITY problem per the trust model in section 1 "
        "(untrusted connector input, reachability, known non-findings). A functional bug that does not "
        "cross the trust boundary is NOT a security finding.\n"
        "2. Assess the CVSS 3.1 vector and base score. If you disagree with the claimed vector or score, "
        "provide your own vector and explain each non-obvious axis choice.\n"
        "3. Assess the real impact: what does the attacker gain, and what bounds it?\n"
        "4. List every concrete inaccuracy you find in the disclosure text, its verification test(s), or "
        "its suggested patch (wrong line refs, claims contradicted by the code/test/patch, patches that do "
        "not fix the stated root cause, tests that would not fail on unmodified source, etc.).\n"
        "Use the mechanical facts where they bear on your judgment; do not re-derive them.\n"
        + CVSS_NOTE + "\n\n"
        "Respond with ONLY a JSON object matching this schema (no prose outside the JSON):\n"
        + _schema_block(EVAL_SCHEMA)
        + "\n\n" + MUST_EMIT
    )
    user_parts.append(task)

    system = (
        "You are an expert Apache Tomcat security auditor. You reason strictly from the provided text, "
        "the trust model, and the mechanical facts. You never invent code or line numbers. You answer with "
        "a single JSON object and nothing else."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": "\n".join(user_parts)}], log


def _adjudication_schema(evaluator_letters: list[str]) -> dict:
    """ADJUDICATION_SCHEMA with a per-evaluator ``model_agreement`` block."""
    agreement: dict = {}
    for letter in evaluator_letters:
        agreement[f"evaluator_{letter}_verdict"] = (
            f"boolean - what evaluator {letter} concluded "
            "(its is_security_problem_per_trust_model ruling)"
        )
    agreement["disagreements"] = [
        "list of strings - where the evaluators or the disclosure disagree, and how you resolved each"
    ]
    schema: dict = {}
    for key, value in ADJUDICATION_SCHEMA.items():
        if key == "edits":
            schema["model_agreement"] = agreement
        schema[key] = value
    return schema


def build_adjudication_prompt(
    bundle_text: str,
    patch_text: str | None,
    test_sources: list[tuple[str, str]],
    mechanical_facts: dict,
    verdicts: list[tuple[str, str, dict]],
    security_model_text: str,
    input_char_budget: int,
    log: TruncationLog | None = None,
) -> tuple[list[dict], TruncationLog]:
    """Build the adjudication messages (bundle + all evaluator verdicts).

    ``verdicts`` is a list of ``(letter, model_key, verdict_dict)`` in stage
    order (A, B, C, ...); one prompt section and one schema key per entry.
    """
    log = log or TruncationLog()
    mech_json = json.dumps(mechanical_facts, indent=2, sort_keys=True)
    verdict_jsons: dict[str, str] = {
        letter: json.dumps(verdict, indent=2, sort_keys=True) for letter, _mk, verdict in verdicts
    }

    parts: list[tuple[str, str]] = [
        ("security_model", security_model_text),
        (f"disclosure:{bundle_slug(bundle_text)}", bundle_text),
        ("suggested_patch", patch_text or "(no embedded diff block found)"),
    ]
    for label, src in test_sources:
        parts.append((f"test_source:{label}", src))
    parts.append(("mechanical_facts", mech_json))
    for letter, _mk, _v in verdicts:
        parts.append((f"verdict_evaluator_{letter}", verdict_jsons[letter]))

    scaffold = 8000 + 1500 * len(verdicts)
    fitted = _fit_sections(parts, max(1000, input_char_budget - scaffold), log)

    user_parts: list[str] = []
    user_parts.append("=== SECURITY MODEL (Apache Tomcat trust model; the standard for triage) ===")
    user_parts.append(fitted.get("security_model", ""))
    slug_key = next(k for k in fitted if k.startswith("disclosure:"))
    user_parts.append("\n=== DISCLOSURE UNDER REVIEW ===")
    user_parts.append(fitted.get(slug_key, ""))
    user_parts.append("\n=== SUGGESTED PATCH ===")
    user_parts.append(fitted.get("suggested_patch", ""))
    for label, _src in test_sources:
        key = f"test_source:{label}"
        if key in fitted and fitted[key]:
            user_parts.append(f"\n=== VERIFICATION TEST SOURCE ({label}) ===")
            user_parts.append(fitted[key])
    user_parts.append("\n=== MECHANICAL FACTS (precomputed; ground truth) ===")
    user_parts.append(fitted.get("mechanical_facts", mech_json))
    for letter, model_key, _v in verdicts:
        user_parts.append(
            f"\n=== EVALUATOR {letter} VERDICT ({model_key}, independent review) ==="
        )
        user_parts.append(verdict_jsons[letter])

    n = len(verdicts)
    task = (
        "\n=== TASK ===\n"
        "You are the final adjudicator. "
        f"{n} independent evaluator models reviewed this disclosure; their verdicts "
        "are above along with precomputed mechanical facts.\n"
        "1. Rule on whether this is a LEGITIMATE security finding per the trust model, weighing all "
        "evaluator verdicts against the disclosure and the mechanical facts. If an evaluator is wrong, say "
        "why in model_agreement.disagreements.\n"
        "2. Assign the REQUIRED classification bucket - every disclosure must land in exactly one: "
        "security_issue (genuine vulnerability per the trust model), hardening (real weakness worth fixing, "
        "not a vulnerability under the trust model), bug (demonstrated functional defect, not security-"
        "relevant), or invalid (the technical claim does not hold). A demonstrated non-security defect is a "
        "bug, never inconclusive.\n"
        "3. State the final CVSS 3.1 vector and base score you stand behind. The mechanical facts include "
        "a computed base score for EVERY vector mentioned in the materials (claimed vector plus any your "
        "evaluator colleagues proposed) - pick from those precomputed scores; if that disagrees with the "
        "disclosure's claimed number, the computed one is authoritative for that vector. For non-"
        "security_issue classifications use the all-N vector AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N (score 0.0) "
        "unless a residual security impact genuinely warrants scoring.\n"
        "4. Summarize the real impact.\n"
        "5. Propose the minimal set of edits needed to make the disclosure artifacts (disclosure markdown, "
        "verification test(s), suggested patch) accurate. For each edit give EXACT current_text that appears "
        "verbatim in the artifact and the proposed replacement. Only propose edits for genuine errors - do "
        "not rewrite style. An empty list is a valid answer.\n"
        + CVSS_NOTE + "\n\n"
        "Respond with ONLY a JSON object matching this schema (no prose outside the JSON):\n"
        + _schema_block(_adjudication_schema([letter for letter, _mk, _v in verdicts]))
        + "\n\n" + MUST_EMIT
    )
    user_parts.append(task)

    system = (
        "You are the final adjudicator in an Apache Tomcat security disclosure review. You decide based on "
        "the trust model, the evidence provided, and the evaluator verdicts above. You answer with a single "
        "JSON object and nothing else."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": "\n".join(user_parts)}], log


def bundle_slug(bundle_text: str) -> str:
    """Derive a stable slug from the disclosure's first H1 line."""
    for line in bundle_text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            slug_chars = [c if c.isalnum() or c in "-_" else "-" for c in title[:48]]
            return "".join(slug_chars).strip("-") or "disclosure"
    return "disclosure"
