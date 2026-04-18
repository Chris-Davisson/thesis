import json
import os
import re
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from db import ensure_db, get_connection, load_config


'''
usage:
python run.py <aggregated_input_id>

Reads model/prompt config from config.toml, sends the scan payload to the LLM,
and writes one model_runs row with the full response. Run multiple times against
the same aggregated_input_id to test different models/prompts — just change config.toml between runs.
'''


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


def load_env():
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    try:
        load_dotenv(env_path)
    except ImportError:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def build_backend(config: dict) -> InferenceBackend:
    backend = config["model"]["backend"]
    name    = config["model"]["name"]

    if backend == "ollama":
        host = config["model"]["ollama_host"]
        if not host:
            raise ValueError("config.toml: backend='ollama' but ollama_host is empty")
        return OllamaBackend(model=name, host=host)

    if backend == "vllm":
        host = config["model"]["vllm_host"]
        if not host:
            raise ValueError("config.toml: backend='vllm' but vllm_host is empty")
        # vLLM exposes an OpenAI-compatible API at /v1 — appended here, not in config
        return OpenAIBackend(model=name, api_key="EMPTY", endpoint=f"{host.rstrip('/')}/v1")

    if backend == "huggingface":
        return HuggingFaceBackend(model=name)

    if backend == "api":
        endpoint = config["model"]["api_endpoint"] or None
        if name.startswith("claude"):
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            return AnthropicBackend(model=name, api_key=api_key)
        else:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            return OpenAIBackend(model=name, api_key=api_key, endpoint=endpoint)

    raise ValueError(
        f"Unknown backend: {backend!r}. "
        f"Expected one of: 'ollama', 'vllm', 'huggingface', 'api'."
    )


def extract_cpe_json(text: str) -> dict | None:
    # Try fenced JSON block first
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Fall back to any JSON object containing a "cpe" key
    match = re.search(r'\{[^{}]*"cpe[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def validate_cpe(cpe: str) -> bool:
    """Return True if cpe is a structurally valid CPE 2.3 string."""
    if not isinstance(cpe, str):
        return False
    parts = cpe.split(":")
    if len(parts) != 13:
        return False
    if parts[0] != "cpe" or parts[1] != "2.3":
        return False
    if parts[2] not in ("h", "o", "a"):
        return False
    # vendor and product must be identified — wildcards defeat the purpose (CVE lookup keys on these fields)
    if not parts[3] or parts[3] == "*":
        return False
    if not parts[4] or parts[4] == "*":
        return False
    return True


def filter_parsed_cpes(parsed: dict) -> dict | None:
    """Drop malformed CPE strings from the parsed output; return None if nothing valid remains."""
    if parsed is None:
        return None
    if "cpes" in parsed:
        valid   = [c for c in parsed["cpes"] if validate_cpe(c)]
        dropped = len(parsed["cpes"]) - len(valid)
        if dropped:
            print(f"  (dropped {dropped} malformed CPE string{'s' if dropped != 1 else ''})")
        return {"cpes": valid} if valid else None
    if "cpe" in parsed:
        val = parsed["cpe"]
        if validate_cpe(val):
            return {"cpe": val}
        print("  (dropped 1 malformed CPE string)")
        return None
    return parsed


def main():
    if len(sys.argv) != 2:
        print("usage: python run.py <aggregated_input_id>")
        sys.exit(1)

    load_env()
    ensure_db()

    config = load_config()

    ai_name     = config["model"]["name"]
    ai_version  = config["model"]["version"]
    max_tokens  = config["model"]["max_tokens"]
    temperature = config["model"]["temperature"]
    top_p       = config["model"]["top_p"]
    seed        = config["model"]["seed"]

    prompt_id = config["prompt"]["prompt_id"]

    agg_input_id = int(sys.argv[1])
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT id, input_payload_json FROM aggregated_inputs WHERE id = ?", (agg_input_id,))
    row = cur.fetchone()
    if row is None:
        print(f"No aggregated input found with id={agg_input_id}. Run ingest.py first.")
        sys.exit(1)

    scan_payload = row["input_payload_json"]

    cur.execute("SELECT prompt_text, prompt_name, prompt_version FROM prompts WHERE id = ?", (prompt_id,))
    prompt_row = cur.fetchone()
    if prompt_row is None:
        print(f"No prompt found with id={prompt_id}. Run seed_prompts.py first.")
        sys.exit(1)
    system_prompt = prompt_row["prompt_text"]
    print(f"using prompt: {prompt_row['prompt_name']} v{prompt_row['prompt_version']} (id={prompt_id})")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": scan_payload},
    ]

    backend        = build_backend(config)
    effective_seed = None if isinstance(backend, AnthropicBackend) else seed

    started_at    = datetime.now(timezone.utc).isoformat()
    status        = "complete"
    raw_output    = ""
    error_text    = None
    parsed_output = None

    try:
        raw_output = backend.chat(
            messages,
            temperature=temperature,
            top_p=top_p,
            seed=effective_seed,
            max_tokens=max_tokens,
        )
        parsed_output = filter_parsed_cpes(extract_cpe_json(raw_output))
    except Exception as e:
        status     = "error"
        error_text = str(e)
        print(f"LLM call failed: {e}")

    ended_at = datetime.now(timezone.utc).isoformat()

    cur.execute("""
        INSERT INTO model_runs (
            aggregated_input_id, experiment_id, prompt_id, trial_number,
            model_name, model_version, temperature, top_p, max_tokens, seed,
            conversation_history_json, raw_output_text, parsed_output_json,
            started_at, ended_at, status, error_text
        ) VALUES (?, NULL, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        agg_input_id, prompt_id,
        ai_name, ai_version, temperature, top_p, max_tokens, effective_seed,
        json.dumps(messages),
        raw_output,
        json.dumps(parsed_output) if parsed_output else None,
        started_at, ended_at, status, error_text,
    ))
    con.commit()

    run_id = cur.lastrowid
    print(f"model_run id={run_id}  status={status}")
    if parsed_output:
        print(json.dumps(parsed_output, indent=2))
    elif status == "complete":
        print("(no JSON parsed from output)")

    con.close()


if __name__ == "__main__":
    main()
