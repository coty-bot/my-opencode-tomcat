"""TOML configuration for the disclosure-verifier pipeline.

All machine-local values — repo/campaign paths, LM Studio URL, evaluator and
adjudicator model keys with their context lengths and input budgets, generation
params — live in a single ``config.toml`` at the tool root instead of being
hardcoded across the CLI and dataclass defaults. Precedence:

    CLI flag  >  config.toml  >  built-in algorithmic defaults (pipeline.py)

The file is validated strictly on load; a malformed or incomplete config fails
fast with an actionable message before any model work starts. Stage order (A,
B, C, ...) follows the ``[[evaluators]]`` order in the file.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import NoReturn

from .pipeline import EvaluatorSpec  # pipeline does not import config: no cycle

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.toml"


class ConfigError(ValueError):
    """Raised when config.toml is missing, malformed, or incomplete."""


def _fail(where: str, msg: str) -> NoReturn:
    raise ConfigError(f"{where}: {msg}")


@dataclass(frozen=True)
class EvaluatorConfig:
    name: str
    model_key: str
    ctx_tokens: int
    input_budget_chars: int


@dataclass(frozen=True)
class VerifierConfig:
    repo_root: Path
    disclosures_dir: Path
    security_model: Path
    jar_dir: Path | None
    lmstudio_url: str
    evaluators: tuple[EvaluatorConfig, ...]
    adjudicator_model: str
    adjudicator_ctx: int
    adjudicator_input_budget_chars: int
    seed: int = 1337
    temperature: float = 0.0
    top_p: float = 1.0
    max_tokens_eval: int = 8192
    max_tokens_final: int = 16384
    run_tests: bool = True
    postpatch: bool = True


def _require_str(table: dict, key: str, where: str) -> str:
    val = table.get(key)
    if not isinstance(val, str) or not val.strip():
        _fail(where, f"'{key}' must be a non-empty string")
    return val


def _require_int(table: dict, key: str, where: str, *, minimum: int = 1) -> int:
    val = table.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        _fail(where, f"'{key}' must be an integer")
    if val < minimum:
        _fail(where, f"'{key}' must be >= {minimum}")
    return val


def _opt_int(table: dict, key: str, where: str, default: int) -> int:
    if key not in table:
        return default
    return _require_int(table, key, where)


def _opt_float(table: dict, key: str, where: str, default: float) -> float:
    val = table.get(key, default)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        _fail(where, f"'{key}' must be a number")
    return float(val)


def _opt_bool(table: dict, key: str, where: str, default: bool) -> bool:
    val = table.get(key, default)
    if not isinstance(val, bool):
        _fail(where, f"'{key}' must be a boolean")
    return val


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> VerifierConfig:
    """Load and strictly validate config.toml."""
    p = Path(path)
    if not p.is_file():
        hint = ""
        if p == DEFAULT_CONFIG_PATH:
            example = p.with_name("config.example.toml")
            hint = f"; create one with: cp {example} {p}"
        raise ConfigError(f"config file not found: {p}{hint}")
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise ConfigError(f"cannot parse {p}: {e}") from e

    where = str(p)
    repo_root = Path(_require_str(raw, "repo_root", where))
    disclosures_dir = Path(_require_str(raw, "disclosures_dir", where))
    security_model = Path(_require_str(raw, "security_model", where))

    jar_raw = raw.get("jar_dir")
    if jar_raw is None:
        jar_dir: Path | None = None
    elif isinstance(jar_raw, str) and jar_raw.strip():
        jar_dir = Path(jar_raw)
    else:
        _fail(where, "'jar_dir' must be a non-empty string (or omitted)")

    lmstudio = raw.get("lmstudio")
    if not isinstance(lmstudio, dict):
        _fail(where, "missing [lmstudio] table")
    lmstudio_url = _require_str(lmstudio, "url", f"{where} [lmstudio]")

    evals_raw = raw.get("evaluators")
    if not isinstance(evals_raw, list) or not evals_raw:
        _fail(where, "'evaluators' must be a non-empty array of tables ([[evaluators]])")
    evaluators: list[EvaluatorConfig] = []
    seen: set[str] = set()
    for i, row in enumerate(evals_raw):
        ew = f"{where} [[evaluators]] #{i + 1}"
        if not isinstance(row, dict):
            _fail(ew, "each evaluator must be a table")
        name = _require_str(row, "name", ew)
        if name in seen:
            _fail(ew, f"duplicate evaluator name {name!r}")
        seen.add(name)
        evaluators.append(
            EvaluatorConfig(
                name=name,
                model_key=_require_str(row, "model_key", ew),
                ctx_tokens=_require_int(row, "ctx_tokens", ew),
                input_budget_chars=_require_int(row, "input_budget_chars", ew),
            )
        )

    adjudicator = raw.get("adjudicator")
    if not isinstance(adjudicator, dict):
        _fail(where, "missing [adjudicator] table")
    adjudicator_model = _require_str(adjudicator, "model_key", f"{where} [adjudicator]")
    adjudicator_ctx = _require_int(adjudicator, "ctx_tokens", f"{where} [adjudicator]")
    adjudicator_budget = _require_int(
        adjudicator, "input_budget_chars", f"{where} [adjudicator]"
    )

    generation = raw.get("generation", {})
    if not isinstance(generation, dict):
        _fail(where, "[generation] must be a table")
    gw = f"{where} [generation]"
    temperature = _opt_float(generation, "temperature", gw, 0.0)
    top_p = _opt_float(generation, "top_p", gw, 1.0)
    if temperature < 0:
        _fail(gw, "'temperature' must be >= 0")
    if not 0 < top_p <= 1:
        _fail(gw, "'top_p' must be in (0, 1]")

    pipeline = raw.get("pipeline", {})
    if not isinstance(pipeline, dict):
        _fail(where, "[pipeline] must be a table")
    pw = f"{where} [pipeline]"

    return VerifierConfig(
        repo_root=repo_root,
        disclosures_dir=disclosures_dir,
        security_model=security_model,
        jar_dir=jar_dir,
        lmstudio_url=lmstudio_url,
        evaluators=tuple(evaluators),
        adjudicator_model=adjudicator_model,
        adjudicator_ctx=adjudicator_ctx,
        adjudicator_input_budget_chars=adjudicator_budget,
        seed=_opt_int(generation, "seed", gw, 1337),
        temperature=temperature,
        top_p=top_p,
        max_tokens_eval=_opt_int(generation, "max_tokens_eval", gw, 8192),
        max_tokens_final=_opt_int(generation, "max_tokens_final", gw, 16384),
        run_tests=_opt_bool(pipeline, "run_tests", pw, True),
        postpatch=_opt_bool(pipeline, "postpatch", pw, True),
    )


def apply_evaluator_overrides(
    cfg: VerifierConfig,
    *,
    models: dict[str, str] | None = None,
    ctx_tokens: dict[str, int] | None = None,
    input_budget_chars: dict[str, int] | None = None,
) -> VerifierConfig:
    """Return a new config with per-evaluator overrides applied by name."""
    models = models or {}
    ctx_tokens = ctx_tokens or {}
    input_budget_chars = input_budget_chars or {}
    known = {e.name for e in cfg.evaluators}
    unknown = (set(models) | set(ctx_tokens) | set(input_budget_chars)) - known
    if unknown:
        raise ConfigError(
            f"unknown evaluator name(s) {sorted(unknown)}; configured: {sorted(known)}"
        )
    evaluators = tuple(
        replace(
            e,
            model_key=models.get(e.name, e.model_key),
            ctx_tokens=ctx_tokens.get(e.name, e.ctx_tokens),
            input_budget_chars=input_budget_chars.get(e.name, e.input_budget_chars),
        )
        for e in cfg.evaluators
    )
    return replace(cfg, evaluators=evaluators)


def select_evaluators(
    cfg: VerifierConfig, requested: list[str] | None = None
) -> tuple[EvaluatorSpec, ...]:
    """Pick the evaluator stages to run.

    ``requested=None`` runs every configured evaluator; otherwise a subset is
    selected by name (duplicates ignored). Stage order always follows the
    config file, so stage letters stay stable regardless of CLI arg order.
    """
    if requested is None:
        chosen = list(cfg.evaluators)
    else:
        if not requested:
            raise ConfigError("no evaluators selected")
        by_name = {e.name: e for e in cfg.evaluators}
        unknown = [n for n in requested if n not in by_name]
        if unknown:
            raise ConfigError(
                f"unknown evaluator name(s) {sorted(set(unknown))}; "
                f"configured: {sorted(by_name)}"
            )
        wanted = set(requested)
        chosen = [e for e in cfg.evaluators if e.name in wanted]

    return tuple(
        EvaluatorSpec(e.name, e.model_key, e.ctx_tokens, e.input_budget_chars)
        for e in chosen
    )
