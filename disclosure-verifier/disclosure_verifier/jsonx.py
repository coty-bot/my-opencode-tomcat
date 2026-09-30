"""Lenient extraction of a JSON verdict object from raw model output."""

from __future__ import annotations

import json
import re
import time


def _balanced_object(text: str, start: int) -> str | None:
    """Return the balanced {...} substring starting at text[start] == '{'."""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _strip_trailing_commas(text: str) -> str:
    """Remove commas whose next non-whitespace char is ``}`` or ``]``.

    String-aware: a literal ``", }"`` inside a JSON string value is left
    alone. Models (especially smaller ones) emit trailing commas regularly;
    strict json.loads rejects the whole object because of one.
    """
    out: list[str] = []
    in_str = False
    esc = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # drop the comma, keep scanning from the whitespace
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract_json(text: str) -> dict | None:
    """Best-effort extraction of a JSON object from model output.

    Order: whole text, ```json fenced block, first balanced top-level object.
    Each candidate is tried strictly first, then with trailing commas stripped
    (a common LLM emit). Returns None when nothing parses to a dict.
    """
    if not text or not text.strip():
        return None
    candidates: list[str] = [text.strip()]
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL):
        candidates.append(m.group(1).strip())
    first_brace = text.find("{")
    if first_brace != -1:
        obj = _balanced_object(text, first_brace)
        if obj is not None:
            candidates.append(obj)
    for cand in candidates:
        for variant in (cand, _strip_trailing_commas(cand)):
            try:
                parsed = json.loads(variant)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def check_required_keys(verdict: dict | None, required_keys: list[str]) -> list[str]:
    """Return a human-readable problem list for missing/empty required keys."""
    problems: list[str] = []
    if verdict is None:
        return ["no JSON object could be parsed from the response"]
    for key in required_keys:
        value = verdict.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            problems.append(f"missing or empty required key {key!r}")
    return problems


EMPTY_CONTENT_PROBLEM = (
    "model returned EMPTY content (no text at all - likely the token budget was "
    "exhausted by reasoning before any answer was produced)"
)


def parse_verdict(raw_text: str, required_keys: list[str]) -> tuple[dict | None, list[str]]:
    """Parse a verdict from raw model output.

    An empty/whitespace-only response is reported as its own distinct problem
    (EMPTY_CONTENT_PROBLEM) rather than the generic "no JSON object" message,
    so stage failures are diagnosable at a glance.
    """
    if raw_text is None or not raw_text.strip():
        return None, [EMPTY_CONTENT_PROBLEM]
    verdict = extract_json(raw_text)
    return verdict, check_required_keys(verdict, required_keys)


def extract_json_candidates(text: str) -> list[dict]:
    """Return every balanced {...} substring of ``text`` that parses to a dict, in order."""
    out: list[dict] = []
    i = 0
    while True:
        start = text.find("{", i)
        if start == -1:
            break
        obj_text = _balanced_object(text, start)
        if obj_text is None:
            break
        for variant in (obj_text, _strip_trailing_commas(obj_text)):
            try:
                parsed = json.loads(variant)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
                break
        i = start + 1
    return out


def recover_from_reasoning(reasoning_full: str, required_keys: list[str]) -> dict | None:
    """Recover a complete verdict from a model's thinking stream.

    Some models (notably Qwen3 with /no_think ignored) finish with
    ``finish_reason=stop`` and empty content after writing their whole answer
    inside the reasoning stream. Try the text as a whole first, then scan every
    balanced object and return the LAST one carrying all required keys - the
    final answer is normally written last in the stream.
    """
    if not reasoning_full or not reasoning_full.strip():
        return None
    verdict = extract_json(reasoning_full)
    if verdict is not None and not check_required_keys(verdict, required_keys):
        return verdict
    for candidate in reversed(extract_json_candidates(reasoning_full)):
        if not check_required_keys(candidate, required_keys):
            return candidate
    return None


RETRY_NUDGE = (
    "Your previous response was not a valid JSON object with all required keys. "
    "Respond again with ONLY the single JSON object - no prose, no code fences. "
    "You MUST write the JSON object as your response text; do not end your turn "
    "without writing it."
)


# Ceiling for the per-retry output budget. Kept at 32768 so that even a large
# stage-C prompt (~25k tokens) plus the max output stays inside a 64k window;
# a higher cap would let a late retry request more output than the context can
# hold and hard-fail with "Context size has been exceeded" on the final attempt.
MAX_TOKENS_CAP = 32768


def call_with_retry(
    runner,
    model: str,
    messages: list[dict],
    gen_params: dict,
    required_keys: list[str],
    max_attempts: int = 3,
) -> tuple[dict | None, list[dict]]:
    """Call ``runner.run(model, msgs, **gen_params)`` until a valid verdict.

    Returns (verdict_or_None, attempts). Each attempt records
    {attempt, raw_text, problems, max_tokens, meta}. On failure the
    conversation is extended with a correction nudge and retried up to
    max_attempts times, doubling max_tokens each retry (capped) so an answer
    truncated by a too-small budget gets room on the next attempt.

    Engine exceptions (HTTP 400/500 — context overflow, speculative-decoding
    crashes, ...) are caught per attempt and retried after a short pause
    instead of killing the stage. A "context size has been exceeded" error
    additionally HALVES the output budget for later attempts so input+output
    fits the window; once shrunk this way it is never re-expanded.

    ``meta`` carries per-attempt diagnostics from the runner when it provides
    them (finish_reason, usage, reasoning clip); empty otherwise.
    """
    convo = list(messages)
    attempts: list[dict] = []
    verdict: dict | None = None
    base_max_tokens = int(gen_params.get("max_tokens") or 0)
    # Output budget state. Normally it DOUBLES per retry (a truncated verdict
    # gets room to finish). When the engine reports a context overflow it is
    # HALVED instead, freeing output budget so input+output fits the window.
    current_max_tokens = base_max_tokens if base_max_tokens > 0 else None
    shrank_for_context = False
    for attempt in range(1, max_attempts + 1):
        params = dict(gen_params)
        if current_max_tokens is not None:
            params["max_tokens"] = current_max_tokens
        meta_sink: dict = {}
        engine_error: str | None = None
        try:
            raw = runner.run(model, convo, meta_sink=meta_sink, **params)
        except Exception as e:  # transient engine errors must not kill a stage
            raw = ""
            engine_error = f"engine error (attempt {attempt}): {e}"
        verdict, problems = parse_verdict(raw, required_keys)
        if engine_error is None and (verdict is None or problems):
            # Some models write the answer inside their thinking stream and
            # finish with empty content. Recover a complete verdict from the
            # full reasoning text when the visible content has none.
            recovered = recover_from_reasoning(
                meta_sink.get("reasoning_full") or "", required_keys
            )
            if recovered is not None:
                verdict = recovered
                problems = []
                meta_sink["recovered_from_reasoning"] = True
        if engine_error is not None:
            problems = [engine_error]
            if "context size has been exceeded" in engine_error.lower() and current_max_tokens:
                # Free output budget so input+output fits the window.
                current_max_tokens = max(current_max_tokens // 2, 1024)
                shrank_for_context = True
            time.sleep(2.0)
        elif base_max_tokens > 0 and not shrank_for_context and attempt < max_attempts:
            # Escalate the output budget for the next retry; never exceed cap.
            current_max_tokens = min(base_max_tokens * (2 ** attempt), MAX_TOKENS_CAP)
        attempts.append(
            {
                "attempt": attempt,
                "raw_text": raw,
                "problems": problems,
                "max_tokens": params.get("max_tokens"),
                "meta": meta_sink or None,
            }
        )
        if verdict is not None and not problems:
            return verdict, attempts
        convo = convo + [
            {"role": "assistant", "content": raw.strip() or "(no output produced)"},
            {"role": "user", "content": RETRY_NUDGE},
        ]
    return verdict, attempts
