#!/usr/bin/env python3
"""
Call the configured LLM backend for a device/experiment pair and write a model_runs row.

Usage:
    python run.py <device_id> <experiment_id> <trial_num>
"""

import json
import os
import re
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from db import ensure_db, get_connection, load_config

MAX_TOKENS_DEFAULT = 2048


# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------

def _load_dotenv():
    """Load .env into os.environ if present. Falls back to manual parse."""
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
    except ImportError:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


# ---------------------------------------------------------------------------
# Backend abstraction
# ---------------------------------------------------------------------------

class InferenceBackend(ABC):
    """Abstract base class for LLM inference backends."""

    @abstractmethod
    def chat(
        self,
        messages: list[dict],
        *,
        temperature: float,
        top_p: float,
        seed: int | None,
        max_tokens: int,
    ) -> str:
        """Send chat messages and return the response text."""


class OllamaBackend(InferenceBackend):
    def __init__(self, model: str, host: str):
        try:
            from ollama import Client
        except ImportError:
            raise ImportError("ollama package not installed. Run: pip install ollama")
        self.model = model
        self.client = Client(host=host)
        models = self.client.list()
        names = [m.model for m in models.models]
        if not any(model in n for n in names):
            raise ValueError(f"Model '{model}' not found in Ollama. Run: ollama pull {model}")

    def chat(self, messages, *, temperature, top_p, seed, max_tokens):
        resp = self.client.chat(
            model=self.model,
            messages=messages,
            options={
                "temperature": temperature,
                "top_p": top_p,
                "seed": seed if seed is not None else 0,
                "num_predict": max_tokens,
            },
        )
        return resp.message.content.strip()


class HuggingFaceBackend(InferenceBackend):
    def __init__(self, model: str):
        try:
            from transformers import pipeline
        except ImportError:
            raise ImportError(
                "transformers/torch not installed. Run: pip install transformers torch"
            )
        self.pipe = pipeline("text-generation", model=model, device_map="auto")

    def chat(self, messages, *, temperature, top_p, seed, max_tokens):
        import torch
        if seed is not None:
            torch.manual_seed(seed)
        outputs = self.pipe(
            messages,
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            do_sample=temperature > 0,
        )
        return outputs[0]["generated_text"][-1]["content"].strip()


class AnthropicBackend(InferenceBackend):
    def __init__(self, model: str, api_key: str):
        try:
            import anthropic as _sdk
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")
        self.model = model
        self.client = _sdk.Anthropic(api_key=api_key)

    def chat(self, messages, *, temperature, top_p, seed, max_tokens):
        # Anthropic separates system from the message list
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        chat_messages = [m for m in messages if m["role"] != "system"]
        kwargs = dict(
            model=self.model,
            messages=chat_messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
        )
        if system:
            kwargs["system"] = system
        # Anthropic does not support seed — omitted intentionally
        resp = self.client.messages.create(**kwargs)
        return resp.content[0].text.strip()


class OpenAIBackend(InferenceBackend):
    def __init__(self, model: str, api_key: str, endpoint: str | None):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")
        self.model = model
        client_kwargs = {"api_key": api_key}
        if endpoint:
            client_kwargs["base_url"] = endpoint
        self.client = OpenAI(**client_kwargs)

    def chat(self, messages, *, temperature, top_p, seed, max_tokens):
        kwargs = dict(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
        )
        if seed is not None:
            kwargs["seed"] = seed
        resp = self.client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content.strip()


def create_backend(cfg: dict) -> InferenceBackend:
    """Instantiate the correct backend from config.toml [model] section."""
    m = cfg["model"]
    backend = m.get("backend", "").strip()
    name = m.get("name", "").strip()
    endpoint = m.get("endpoint", "").strip() or None

    if not backend:
        print("ERROR: [model] backend is not set in config.toml")
        sys.exit(1)
    if not name:
        print("ERROR: [model] name is not set in config.toml")
        sys.exit(1)

    if backend == "ollama":
        return OllamaBackend(model=name, host=endpoint or "http://127.0.0.1:11434")

    if backend == "huggingface":
        return HuggingFaceBackend(model=name)

    if backend == "api":
        if "claude" in name.lower():
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                print("ERROR: ANTHROPIC_API_KEY not set in .env or environment")
                sys.exit(1)
            return AnthropicBackend(model=name, api_key=api_key)
        else:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                print("ERROR: OPENAI_API_KEY not set in .env or environment")
                sys.exit(1)
            return OpenAIBackend(model=name, api_key=api_key, endpoint=endpoint)

    print(f"ERROR: Unknown backend '{backend}'. Use: ollama, huggingface, api")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def parse_cpes(raw: str) -> list[str]:
    """Extract CPE 2.3 strings from LLM output.

    Tries a fenced JSON block first, then a bare JSON object, then regex
    over the raw text. Returns an empty list if nothing is found.
    """
    # Fenced JSON block
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fenced:
        try:
            data = json.loads(fenced.group(1))
            if isinstance(data.get("cpes"), list):
                return [c for c in data["cpes"] if c.startswith("cpe:2.3:")]
        except json.JSONDecodeError:
            pass

    # Bare JSON object with a cpes key
    bare = re.search(r'\{[^{}]*"cpes"\s*:\s*\[.*?\]\s*\}', raw, re.DOTALL)
    if bare:
        try:
            data = json.loads(bare.group(0))
            if isinstance(data.get("cpes"), list):
                return [c for c in data["cpes"] if c.startswith("cpe:2.3:")]
        except json.JSONDecodeError:
            pass

    # Last resort: grab any CPE strings directly
    return re.findall(r"cpe:2\.3:[haox*\-]:\S+", raw)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 4:
        print("Usage: python run.py <device_id> <experiment_id> <trial_num>")
        sys.exit(1)

    device_id = int(sys.argv[1])
    experiment_id = int(sys.argv[2])
    trial_num = int(sys.argv[3])

    _load_dotenv()
    ensure_db()

    cfg = load_config()
    con = get_connection()
    try:
        _run(con, cfg, device_id, experiment_id, trial_num)
    finally:
        con.close()


def _run(con, cfg, device_id, experiment_id, trial_num):
    # --- Load experiment ---
    exp = con.execute(
        "SELECT * FROM experiments WHERE id = ?", (experiment_id,)
    ).fetchone()
    if not exp:
        print(f"ERROR: experiment_id {experiment_id} not found")
        sys.exit(1)

    prompt_id = exp["prompt_id"]
    temperature = exp["temperature"] if exp["temperature"] is not None else 0.0
    top_p = exp["top_p"] if exp["top_p"] is not None else 1.0
    seed = exp["seed"]
    model_name = exp["model_name"] or cfg["model"]["name"]
    model_version = exp["model_version"] or cfg["model"].get("version", "")

    # --- Load prompt ---
    prompt_row = con.execute(
        "SELECT prompt_text FROM prompts WHERE id = ?", (prompt_id,)
    ).fetchone()
    if not prompt_row:
        print(f"ERROR: prompt_id {prompt_id} not found in prompts table")
        sys.exit(1)
    prompt_text = prompt_row["prompt_text"]

    # --- Load aggregated input for device ---
    agg = con.execute(
        """
        SELECT ai.id, ai.input_payload_json
          FROM aggregated_inputs ai
          JOIN scan_sessions ss ON ai.scan_session_id = ss.id
         WHERE ss.device_id = ?
           AND ai.variant_name = 'plain-text'
         ORDER BY ai.created_at DESC
         LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if not agg:
        print(f"ERROR: No plain-text aggregated_input found for device_id {device_id}")
        sys.exit(1)

    aggregated_input_id = agg["id"]
    input_payload = agg["input_payload_json"]

    # --- Build messages ---
    messages = [
        {"role": "system", "content": prompt_text},
        {"role": "user", "content": input_payload},
    ]

    # --- Call LLM ---
    backend = create_backend(cfg)

    started_at = datetime.now(timezone.utc).isoformat()
    raw_output = ""
    status = "success"
    error_text = None

    try:
        raw_output = backend.chat(
            messages,
            temperature=temperature,
            top_p=top_p,
            seed=seed,
            max_tokens=MAX_TOKENS_DEFAULT,
        )
    except Exception as e:
        status = "error"
        error_text = str(e)
        print(f"ERROR during LLM call: {e}")

    ended_at = datetime.now(timezone.utc).isoformat()

    # --- Parse output ---
    parsed_cpes = parse_cpes(raw_output) if status == "success" else []
    parsed_output = json.dumps({"cpes": parsed_cpes})

    # --- Write model_runs row ---
    cur = con.execute(
        """
        INSERT INTO model_runs (
            aggregated_input_id, experiment_id, prompt_id,
            trial_number, model_name, model_version,
            temperature, top_p, max_tokens, seed,
            conversation_history_json,
            raw_output_text, parsed_output_json,
            started_at, ended_at, status, error_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            aggregated_input_id, experiment_id, prompt_id,
            trial_num, model_name, model_version,
            temperature, top_p, MAX_TOKENS_DEFAULT, seed,
            json.dumps(messages),
            raw_output, parsed_output,
            started_at, ended_at, status, error_text,
        ),
    )
    run_id = cur.lastrowid
    con.commit()

    if status == "success":
        print(f"OK  model_run {run_id} — CPEs found: {len(parsed_cpes)}")
        for cpe in parsed_cpes:
            print(f"    {cpe}")
    else:
        print(f"FAIL model_run {run_id} written with status=error")
        sys.exit(1)


if __name__ == "__main__":
    main()
