"""CVSS v3.1 base-score calculation and vector parsing (pure stdlib).

Implements the official CVSS v3.1 specification formulas so the pipeline can
mechanically verify a disclosure's claimed base score without any external
dependency.
"""

from __future__ import annotations

import math
import re
from decimal import Decimal, ROUND_CEILING

# Base-metric values per the CVSS v3.1 spec (section 5.4).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"R": 0.62, "N": 0.85}
_IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}

_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """Raised for malformed CVSS vectors or unparseable scores."""


def roundup(x: float) -> float:
    """CVSS 'Roundup': round up to the nearest single decimal place.

    Uses Decimal on a noise-stripped value so floating-point artifacts
    (e.g. 4.0000000001 or 5.299999999) cannot push the result across a
    0.1 boundary in either direction.
    """
    if x < 0:
        raise CvssError(f"roundup of negative value {x!r}")
    cleaned = round(x, 9)
    return float((Decimal(repr(cleaned)) * 10).to_integral_value(rounding=ROUND_CEILING) / 10)


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS 3.1 vector string into {metric: value}.

    Accepts an optional ``CVSS:3.1/`` prefix and is case-insensitive on both
    metric names and values. All eight base metrics are required.
    """
    text = vector.strip()
    if text.upper().startswith("CVSS:3.1/"):
        text = text[len("CVSS:3.1/"):]
    parts = [p for p in text.split("/") if p != ""]
    if len(parts) != 8:
        raise CvssError(f"expected 8 metrics, got {len(parts)}: {vector!r}")
    out: dict[str, str] = {}
    for part in parts:
        name, sep, value = part.partition(":")
        if not sep or not value:
            raise CvssError(f"malformed metric element {part!r} in {vector!r}")
        name = name.upper()
        if name not in _METRICS:
            raise CvssError(f"unknown metric {name!r} in {vector!r}")
        if name in out:
            raise CvssError(f"duplicate metric {name!r} in {vector!r}")
        out[name] = value.upper()
    missing = [m for m in _METRICS if m not in out]
    if missing:
        raise CvssError(f"missing metrics {missing} in {vector!r}")
    return out


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score (0.0-10.0, one decimal place)."""
    v = parse_vector(vector)

    for name, table in (("AV", _AV), ("AC", _AC), ("UI", _UI)):
        if v[name] not in table:
            raise CvssError(f"invalid {name} value {v[name]!r}")
    scope_changed = v["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    if v["PR"] not in pr_table:
        raise CvssError(f"invalid PR value {v['PR']!r} for S:{v['S']}")
    if v["S"] not in ("U", "C"):
        raise CvssError(f"invalid S value {v['S']!r}")
    for name in ("C", "I", "A"):
        if v[name] not in _IMPACT:
            raise CvssError(f"invalid {name} value {v[name]!r}")

    iss = 1.0 - ((1.0 - _IMPACT[v["C"]]) * (1.0 - _IMPACT[v["I"]]) * (1.0 - _IMPACT[v["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * _AV[v["AV"]] * _AC[v["AC"]] * pr_table[v["PR"]] * _UI[v["UI"]]

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)
    return roundup(score)


_VECTOR_RE = re.compile(
    r"(?:CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)


def find_vectors(text: str) -> list[str]:
    """Return all complete CVSS 3.1 base vectors found in free text, in order."""
    return [m.group(0).strip() for m in _VECTOR_RE.finditer(text)]


def candidates_from_texts(texts: list[str]) -> list[dict]:
    """Compute base scores for every distinct complete CVSS 3.1 vector in ``texts``.

    Lets the pipeline hand adjudicators precomputed scores for any vector
    mentioned anywhere (disclosure, evaluator verdicts) so no model has to do
    CVSS arithmetic from memory. Invalid vectors are skipped silently; order
    of first appearance is preserved and duplicates (modulo prefix/case) drop.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for vec in find_vectors(text):
            key = re.sub(r"(?i)^CVSS:3\.1/", "", vec).upper()
            if key in seen:
                continue
            seen.add(key)
            try:
                out.append({"vector": vec, "base_score": base_score(vec)})
            except CvssError:
                pass
    return out


def extract_cvss_claim(md_text: str) -> tuple[str | None, float | None]:
    """Extract (vector, claimed_base_score) from disclosure markdown.

    The score is the first ``base score``-style number within 160 chars after
    the first vector occurrence; returns (None, None) when absent.
    """
    vectors = find_vectors(md_text)
    if not vectors:
        return None, None
    anchor = md_text.find(vectors[0])
    window = md_text[anchor : anchor + len(vectors[0]) + 160]
    m = re.search(r"base\s+score[^0-9]{0,24}?(\d\.\d)", window, re.IGNORECASE)
    if not m:
        return vectors[0], None
    try:
        score = float(m.group(1))
    except ValueError as exc:  # pragma: no cover - regex guarantees digits
        raise CvssError(f"unparseable claimed score {m.group(1)!r}") from exc
    if not 0.0 <= score <= 10.0:
        raise CvssError(f"claimed score out of range: {score}")
    return vectors[0], score
