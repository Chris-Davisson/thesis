#!/usr/bin/env python3
"""
Sweep all prompts against a single scan through the configured LLM.

Reads model/prompt config from config.toml, sends the scan payload to the LLM
once per prompt in the prompts collection, and writes one model_runs doc per
response.

Usage:
    python run.py <scan_id>
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from db import ensure_db, get_db, load_config, next_id


DOUBLED_DELIMITER = "\n\n--- REPEAT ---\n\n"


def build_messages(system_prompt: str, scan_payload: str, doubled: bool) -> list[dict]:
    """
    Normal: standard system+user split.
    Doubled: single user message with [system, scan, DELIM, system, scan] — the
    system role is intentionally dropped so the instructions bookend the data.
    """
    if doubled:
        block = f"{system_prompt}\n\n{scan_payload}"
        return [{"role": "user", "content": f"{block}{DOUBLED_DELIMITER}{block}"}]
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": scan_payload},
    ]


class InferenceBackend(ABC):
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


class CLIBackend(InferenceBackend):
    """Generic CLI inference backend.

    Spawns the configured command with the prompt fed via stdin, captures
    stdout as the model response. Works with any CLI that takes a prompt on
    stdin and emits the response on stdout — e.g. Claude Code (`claude -p`),
    gemini-cli, llm, etc. Sampling args are accepted for interface parity
    but not forwarded; bake them into cli_command if the CLI supports them.
    """

    def __init__(self, command: list[str], timeout: int = 600):
        if not command:
            raise ValueError("config.toml: backend='cli' but cli_command is empty")
        # Resolve the binary up front so PATHEXT / .cmd shims work on Windows
        resolved = shutil.which(command[0]) or command[0]
        self.command = [resolved, *command[1:]]
        self.timeout = timeout

    def chat(self, messages, *, temperature, top_p, seed, max_tokens):
        prompt = "\n\n".join(m["content"] for m in messages)
        try:
            result = subprocess.run(
                self.command,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                encoding="utf-8",
            )
        except FileNotFoundError as e:
            raise RuntimeError(f"CLI binary not found: {self.command[0]}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"CLI timed out after {self.timeout}s: {' '.join(self.command)}") from e

        if result.returncode != 0:
            stderr = (result.stderr or "").strip() or "(no stderr)"
            raise RuntimeError(
                f"CLI '{' '.join(self.command)}' exited {result.returncode}: {stderr}"
            )
        return (result.stdout or "").strip()


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
        api_key  = os.environ.get("OPENAI_API_KEY", "")
        return OpenAIBackend(model=name, api_key=api_key, endpoint=endpoint)

    if backend == "cli":
        command = config["model"].get("cli_command") or []
        timeout = config["model"].get("cli_timeout", 600)
        return CLIBackend(command=command, timeout=timeout)

    raise ValueError(
        f"Unknown backend: {backend!r}. "
        f"Expected one of: 'ollama', 'vllm', 'huggingface', 'api', 'cli'."
    )


def extract_cpe_json(text: str) -> dict | None:
    # Fenced JSON block first
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Any JSON object containing a "cpe" key
    match = re.search(r'\{[^{}]*"cpe[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def validate_cpe(cpe: str) -> bool:
    """True if cpe is a structurally valid CPE 2.3 string with vendor+product set."""
    if not isinstance(cpe, str):
        return False
    parts = cpe.split(":")
    # CPE 2.3 has 13 fields max, but trailing wildcards can be omitted
    # Minimum: cpe:2.3:part:vendor:product (5 parts)
    if len(parts) < 5:
        return False
    if parts[0] != "cpe" or parts[1] != "2.3":
        return False
    if parts[2] not in ("h", "o", "a"):
        return False
    # vendor and product must be identified — wildcards defeat the purpose
    if not parts[3] or parts[3] == "*":
        return False
    if not parts[4] or parts[4] == "*":
        return False
    return True


def filter_parsed_cpes(parsed: dict) -> dict | None:
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
    parser = argparse.ArgumentParser(description="Sweep all prompts x 2 modes against a single scan")
    parser.add_argument("scan_id", type=int, help="scan _id to sweep")
    parser.add_argument("--model", help="Override config.toml model.name (e.g. qwen3.5:cloud)")
    args = parser.parse_args()

    load_env()
    ensure_db()

    config = load_config()
    if args.model:
        config["model"]["name"] = args.model
    ai_name     = config["model"]["name"]
    ai_version  = config["model"]["version"]
    max_tokens  = config["model"]["max_tokens"]
    temperature = config["model"]["temperature"]
    top_p       = config["model"]["top_p"]
    seed        = config["model"]["seed"]

    scan_id = args.scan_id
    db = get_db()

    scan = db.scans.find_one({"_id": scan_id}, {"payload": 1})
    if scan is None:
        print(f"No scan found with id={scan_id}. Run ingest.py first.")
        sys.exit(1)

    scan_payload = scan["payload"]

    prompts = list(db.prompts.find({}).sort("_id"))
    if not prompts:
        print("No prompts in the database. Run seed_prompts.py first.")
        sys.exit(1)

    backend = build_backend(config)

    n_prompts = len(prompts)
    total     = n_prompts * 2
    succeeded = 0
    failed    = 0

    print(f"\nSweeping {n_prompts} prompt(s) x 2 modes (normal, doubled) against scan_id={scan_id} on {ai_name}\n")

    for doubled in (False, True):
        mode_label = "doubled" if doubled else "normal"
        print(f"--- mode: {mode_label} ---")

        for i, prompt in enumerate(prompts, start=1):
            prompt_id      = prompt["_id"]
            prompt_name    = prompt["prompt_name"]
            prompt_version = prompt["prompt_version"]
            system_prompt  = prompt["prompt_text"]

            print(f"  [{i}/{n_prompts}] {mode_label}: {prompt_name} v{prompt_version} (id={prompt_id}) ... ", end="", flush=True)

            messages = build_messages(system_prompt, scan_payload, doubled)

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
                    seed=seed,
                    max_tokens=max_tokens,
                )
                parsed_output = filter_parsed_cpes(extract_cpe_json(raw_output))
            except Exception as e:
                status     = "error"
                error_text = str(e)

            ended_at = datetime.now(timezone.utc).isoformat()

            # trial_number increments per (scan, prompt, doubled, model.name) — re-running
            # run.py against the same scan accumulates trials for variance analysis.
            trial_number = db.model_runs.count_documents({
                "scan_id":    scan_id,
                "prompt_id":  prompt_id,
                "doubled":    doubled,
                "model.name": ai_name,
            }) + 1

            run_id = next_id(db, "model_runs")
            db.model_runs.insert_one({
                "_id":           run_id,
                "scan_id":       scan_id,
                "prompt_id":     prompt_id,
                "trial_number":  trial_number,
                "doubled":       doubled,
                "model": {
                    "name":        ai_name,
                    "version":     ai_version,
                    "temperature": temperature,
                    "top_p":       top_p,
                    "max_tokens":  max_tokens,
                    "seed":        seed,
                },
                "messages":      messages,
                "raw_output":    raw_output,
                "parsed_output": parsed_output,
                "started_at":    started_at,
                "ended_at":      ended_at,
                "status":        status,
                "error":         error_text,
                "scores":        [],
            })

            if status == "error":
                failed += 1
                print(f"ERROR (run id={run_id}): {error_text}")
            elif parsed_output:
                n_cpes = len(parsed_output.get("cpes", [])) if "cpes" in parsed_output else 1
                succeeded += 1
                print(f"ok (run id={run_id}, {n_cpes} CPE{'s' if n_cpes != 1 else ''})")
            else:
                succeeded += 1
                print(f"ok (run id={run_id}, no JSON parsed)")

    print(f"\nDone. {succeeded} succeeded, {failed} failed, {total} total.")


if __name__ == "__main__":
    main()
