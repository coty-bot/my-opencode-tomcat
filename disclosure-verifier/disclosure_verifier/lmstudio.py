"""LM Studio local-server (API v1) client and model-lifecycle management.

Stdlib-only (urllib). The lifecycle manager guarantees "one model in VRAM at
a time": it snapshots whatever is loaded, unloads everything before loading a
stage model, and the pipeline unloads everything again on exit - so nothing
lingers in VRAM to contend with an agent or other job that shares this LM
Studio instance.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_BASE_URL = "http://127.0.0.1:1234"

# Fields the load endpoint is documented to accept; used as a fallback when a
# full captured config is rejected on restore.
KNOWN_LOAD_FIELDS = (
    "context_length",
    "eval_batch_size",
    "flash_attention",
    "num_experts",
    "offload_kv_cache_to_gpu",
)


class LmStudioError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class LoadedInstance:
    model_key: str
    instance_id: str
    config: dict = field(default_factory=dict)


class LmStudioClient:
    # Generous on purpose: a stage generation can take many minutes when the
    # card is shared (e.g. an agent model auto-reloads mid-run and forces CPU
    # offload). A short read timeout would kill otherwise-fine long generations.
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 3600.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # -- low-level ---------------------------------------------------------

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(
            url, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise LmStudioError(
                f"{method} {path} failed with HTTP {e.code}: {err_body[:500]}",
                status=e.code,
                body=err_body,
            ) from None
        except urllib.error.URLError as e:
            raise LmStudioError(f"{method} {path} connection error: {e.reason}") from None
        if not body.strip():
            return {}
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as e:
            raise LmStudioError(f"{method} {path} returned non-JSON body: {body[:200]!r}") from e
        if not isinstance(parsed, dict):
            return {"data": parsed}
        return parsed

    # -- API v1 ------------------------------------------------------------

    def list_models(self) -> list[dict]:
        """Return normalized model rows: {key, max_context_length, loaded_instances}."""
        payload = self._request("GET", "/api/v1/models")
        models = payload.get("models") or payload.get("data") or []
        out = []
        for m in models:
            if not isinstance(m, dict):
                continue
            instances = [
                {
                    "id": inst.get("id", ""),
                    "config": dict(inst.get("config") or {}),
                }
                for inst in (m.get("loaded_instances") or [])
                if isinstance(inst, dict)
            ]
            out.append(
                {
                    "key": m.get("key") or m.get("id", ""),
                    "max_context_length": m.get("max_context_length"),
                    "quantization": m.get("quantization"),
                    "loaded_instances": instances,
                }
            )
        return out

    def loaded_instances(self) -> list[LoadedInstance]:
        result = []
        for row in self.list_models():
            for inst in row["loaded_instances"]:
                if inst["id"]:
                    result.append(
                        LoadedInstance(model_key=row["key"], instance_id=inst["id"], config=inst["config"])
                    )
        return result

    def load_model(self, model_key: str, **config) -> dict:
        payload = {"model": model_key}
        payload.update(config)
        return self._request("POST", "/api/v1/models/load", payload)

    def unload_instance(self, instance_id: str) -> dict:
        return self._request("POST", "/api/v1/models/unload", {"instance_id": instance_id})

    # -- OpenAI-compatible chat --------------------------------------------

    def chat(
        self,
        model: str,
        messages: list[dict],
        temperature: float = 0.0,
        top_p: float = 1.0,
        seed: int | None = None,
        max_tokens: int = 4096,
        chat_template_kwargs: dict | None = None,
    ) -> tuple[str, dict]:
        """Return ``(content, meta)`` where meta carries finish_reason/usage and a
        clipped ``reasoning_content`` for forensics when content comes back empty."""
        payload: dict = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if seed is not None:
            payload["seed"] = seed
        if chat_template_kwargs:
            payload["chat_template_kwargs"] = chat_template_kwargs
        resp = self._request("POST", "/v1/chat/completions", payload)
        try:
            choice = resp["choices"][0]
            message = choice.get("message") or {}
            content = str(message.get("content") or "")
        except (KeyError, IndexError, TypeError) as e:
            raise LmStudioError(f"unexpected chat completion shape: {str(resp)[:300]}") from e
        reasoning = str((message or {}).get("reasoning_content") or "")
        meta = {
            "finish_reason": choice.get("finish_reason"),
            "usage": resp.get("usage"),
            "reasoning_chars": len(reasoning),
            "reasoning_head": reasoning[:1500],
            "reasoning_tail": reasoning[-1500:] if len(reasoning) > 3000 else "",
            # Full text so a verdict written inside the thinking stream can be
            # recovered when content comes back empty (some models finish with
            # finish_reason=stop and no content after long reasoning).
            "reasoning_full": reasoning,
        }
        return content, meta


class LmStudioRunner:
    """Adapter exposing the pipeline's ``run(model, messages, **params)`` API.

    Two guards live here so every stage call gets them for free:

    - Thinking suppression. Qwen3-family thinking models can spend their entire
      max_tokens budget on internal reasoning and return EMPTY content
      (finish_reason=length, all tokens in reasoning_content). The primary
      mechanism is ``chat_template_kwargs={"enable_thinking": False}`` — the
      model's own chat-template switch, which /no_think prompt text does not
      reliably trigger. If the server rejects that kwarg for a given model the
      call is retried without it (and the fallback is remembered per process).
      ``/no_think`` is still appended as belt-and-braces; inert elsewhere.
    - ``evict_others`` unloads any intruding model instances before the call so
      generation always starts with exactly one model resident, even if an
      agent or user auto-reloaded another model mid-run (which forces CPU
      offload and can starve/truncate the stage generation).
    """

    NO_THINK = "/no_think"
    # Models whose chat template accepts enable_thinking. Matched on the model
    # key prefix so new qwen3.x loads get suppression automatically.
    THINKING_SUPPRESS_PREFIXES = ("qwen/",)
    _kwargs_rejected: set[str] = set()

    def __init__(self, client: LmStudioClient, lifecycle: "ModelLifecycle | None" = None):
        self.client = client
        self.lifecycle = lifecycle

    def run(self, model: str, messages: list[dict], meta_sink: dict | None = None, **params) -> str:
        msgs = [dict(m) for m in messages]
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i].get("role") == "user" and isinstance(msgs[i].get("content"), str):
                if self.NO_THINK not in msgs[i]["content"]:
                    msgs[i]["content"] = msgs[i]["content"] + "\n\n" + self.NO_THINK
                break
        if self.lifecycle is not None:
            self.lifecycle.evict_others(model)
        use_kwargs = (
            model.startswith(self.THINKING_SUPPRESS_PREFIXES)
            and model not in self._kwargs_rejected
        )
        try:
            content, meta = self.client.chat(
                model, msgs, chat_template_kwargs={"enable_thinking": False} if use_kwargs else None, **params
            )
        except LmStudioError as e:
            body = str(e).lower()
            if use_kwargs and ("chat_template" in body or "enable_thinking" in body):
                # This model's template rejects the kwarg; fall back for good.
                self._kwargs_rejected.add(model)
                if meta_sink is not None:
                    meta_sink["thinking_suppression_fallback"] = str(e)[:200]
                content, meta = self.client.chat(model, msgs, **params)
            else:
                raise
        if meta_sink is not None:
            meta_sink.update(meta)
        return content


class ModelLifecycle:
    """One-model-at-a-time loading with snapshot/restore semantics."""

    def __init__(self, client: LmStudioClient):
        self.client = client
        self._snapshot: list[LoadedInstance] | None = None
        self.events: list[str] = []  # audit trail of lifecycle actions

    def snapshot(self) -> list[LoadedInstance]:
        if self._snapshot is not None:
            return self._snapshot
        self._snapshot = self.client.loaded_instances()
        for inst in self._snapshot:
            self.events.append(f"snapshot: {inst.model_key} (instance {inst.instance_id})")
        return self._snapshot

    def unload_all(self) -> list[str]:
        unloaded = []
        for inst in self.client.loaded_instances():
            self.client.unload_instance(inst.instance_id)
            unloaded.append(inst.instance_id)
            self.events.append(f"unloaded: {inst.model_key} (instance {inst.instance_id})")
        return unloaded

    def load(self, model_key: str, **config) -> dict:
        result = self.client.load_model(model_key, **config)
        self.events.append(f"loaded: {model_key} config={json.dumps(config, sort_keys=True)}")
        # Read back the ACTUAL context length: LM Studio can silently load a
        # smaller window than requested (e.g. VRAM not yet freed from an
        # unloading model), which later surfaces as "context size exceeded".
        if "context_length" in config:
            try:
                for inst in self.client.loaded_instances():
                    if inst.model_key == model_key:
                        actual = (inst.config or {}).get("context_length")
                        if actual != config["context_length"]:
                            self.events.append(
                                f"context-mismatch: {model_key} "
                                f"requested={config['context_length']} actual={actual}"
                            )
            except LmStudioError as e:
                self.events.append(f"load-verify-failed: {model_key}: {e}")
        return result

    def evict_others(self, model_key: str) -> list[str]:
        """Unload every loaded instance except ``model_key``.

        Guarantees a single-model-at-a-time generation even when something else
        (an agent turn, the LM Studio UI) auto-loads another model mid-run.
        """
        evicted = []
        for inst in self.client.loaded_instances():
            if inst.model_key != model_key:
                self.client.unload_instance(inst.instance_id)
                evicted.append(inst.instance_id)
                self.events.append(f"evicted-intruder: {inst.model_key} (instance {inst.instance_id})")
        return evicted

    def stage(self, model_key: str, **config):
        """Context manager: unload everything, then load exactly one model.

        Every stage starts from a clean slate with the stage model loaded at
        an explicit config (e.g. context_length), so results do not depend on
        whatever happened to be resident in LM Studio beforehand. The stage
        model is left loaded on exit; ``restore()`` re-establishes the
        pre-pipeline state when the run finishes.
        """

        class _Stage:
            def __enter__(self_inner):
                last_err: LmStudioError | None = None
                for attempt in range(1, 4):
                    try:
                        self.unload_all()
                        self.load(model_key, **config)
                        return model_key
                    except LmStudioError as e:
                        # Transient (VRAM not freed yet after unloading an
                        # in-use model, server hiccup): back off and retry.
                        last_err = e
                        if attempt < 3:
                            self.events.append(
                                f"stage-entry-retry {attempt}: {model_key}: {e}"
                            )
                            time.sleep(5.0)
                assert last_err is not None
                raise last_err

            def __exit__(self_inner, exc_type, exc, tb):
                # Leave the stage model loaded; pipeline unloads all at the end.
                return False

        return _Stage()

    def restore(self) -> list[dict]:
        """Reload every instance captured by snapshot(), with its config."""
        results = []
        snap = self._snapshot or []
        for inst in snap:
            entry = {"model_key": inst.model_key, "instance_id": inst.instance_id}
            try:
                self.client.load_model(inst.model_key, **inst.config)
                entry["status"] = "restored-full-config"
                self.events.append(f"restored: {inst.model_key}")
            except LmStudioError as e:
                filtered = {k: v for k, v in inst.config.items() if k in KNOWN_LOAD_FIELDS}
                try:
                    self.client.load_model(inst.model_key, **filtered)
                    entry["status"] = "restored-filtered-config"
                    entry["dropped_fields"] = sorted(set(inst.config) - set(filtered))
                    self.events.append(f"restored (filtered): {inst.model_key}")
                except LmStudioError as e2:
                    entry["status"] = "restore-failed"
                    entry["error"] = str(e2)
                    self.events.append(f"RESTORE FAILED: {inst.model_key}: {e2}")
            results.append(entry)
        return results
