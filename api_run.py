#!/usr/bin/env python3
"""
api_run.py — Sweep all scans × prompts against a hosted LLM API
(OpenAI, Anthropic, or Google Gemini).

Counterpart to local_run.py: same DB schema, same sweep semantics
(every scan × prompt × {single, doubled} combination), but driven by a
hosted API instead of a local vLLM server.

No sampling knobs. Temperature, top-p, top-k, and seed are intentionally
omitted — every API call is made with provider defaults so results
reflect provider-default behavior. Guided decoding is also
not exposed (no equivalent across all three providers).

Usage:
    python api_run.py --company openai    --model gpt-5
    python api_run.py --company anthropic --model claude-opus-4-7
    python api_run.py --company gemini    --model gemini-2.5-pro
    python api_run.py --company openai    --model gpt-5 --api-key sk-...
    python api_run.py --company anthropic --model claude-opus-4-7 --scan-ids 1 2 3

API keys are read from the environment by default:
  - OPENAI_API_KEY
  - ANTHROPIC_API_KEY
  - GEMINI_API_KEY  (or GOOGLE_API_KEY)
"""

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from db import ensure_db, get_db, next_id


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DOUBLED_DELIMITER = "\n\n--- REPEAT ---\n\n"

COMPANIES = ("openai", "anthropic", "gemini")

ENV_KEYS = {
    "openai":    ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini":    ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class RunTask:
    """A single inference task to execute."""
    scan_id: int
    scan_payload: str
    prompt_id: int
    prompt_name: str
    system_prompt: str
    doubled: bool


# --------------------------------------------------------------------------- #
# Message building (DB-canonical, OpenAI-style)
# --------------------------------------------------------------------------- #

def build_messages(system_prompt: str, scan_payload: str, doubled: bool) -> list[dict]:
    """
    Normal: standard system+user split.
    Doubled: single user message with [system, scan, DELIM, system, scan].

    This is the canonical representation stored in model_runs.messages,
    regardless of which provider was invoked.
    """
    if doubled:
        block = f"{system_prompt}\n\n{scan_payload}"
        return [{"role": "user", "content": f"{block}{DOUBLED_DELIMITER}{block}"}]
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": scan_payload},
    ]


# --------------------------------------------------------------------------- #
# CPE extraction (same as local_run.py)
# --------------------------------------------------------------------------- #

def extract_cpe_json(text: str) -> dict | None:
    """Extract JSON containing CPE(s) from model output."""
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
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
    if len(parts) < 5:
        return False
    if parts[0] != "cpe" or parts[1] != "2.3":
        return False
    if parts[2] not in ("h", "o", "a"):
        return False
    if not parts[3] or parts[3] == "*":
        return False
    if not parts[4] or parts[4] == "*":
        return False
    return True


def filter_parsed_cpes(parsed: dict) -> dict | None:
    """Filter out malformed CPEs from parsed output."""
    if parsed is None:
        return None
    if "cpes" in parsed:
        valid = [c for c in parsed["cpes"] if validate_cpe(c)]
        return {"cpes": valid} if valid else None
    if "cpe" in parsed:
        val = parsed["cpe"]
        if validate_cpe(val):
            return {"cpe": val}
        return None
    return parsed


# --------------------------------------------------------------------------- #
# Provider clients — one async generate(system, user, max_tokens) → str
# --------------------------------------------------------------------------- #

class Provider:
    """Common async interface across OpenAI / Anthropic / Gemini."""

    name: str

    async def generate(self, system_prompt: str, user_content: str,
                       max_tokens: int) -> str:
        raise NotImplementedError


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self, api_key: str, model: str):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = model

    async def generate(self, system_prompt, user_content, max_tokens):
        if system_prompt:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_content},
            ]
        else:
            messages = [{"role": "user", "content": user_content}]
        # Newer OpenAI models (o-series, gpt-5) reject `max_tokens` and require
        # `max_completion_tokens`. The new name is also accepted on the older
        # GPT-4 family, so it's the forward-compatible choice.
        resp = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_completion_tokens=max_tokens,
        )
        return (resp.choices[0].message.content or "").strip()


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str):
        from anthropic import AsyncAnthropic
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model

    async def generate(self, system_prompt, user_content, max_tokens):
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": user_content}],
        )
        if system_prompt:
            kwargs["system"] = system_prompt
        resp = await self.client.messages.create(**kwargs)
        # Concatenate text blocks; ignore tool_use / thinking blocks
        return "".join(
            getattr(b, "text", "") for b in (resp.content or [])
        ).strip()


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(self, api_key: str, model: str):
        from google import genai
        from google.genai import types
        self._types = types
        self.client = genai.Client(api_key=api_key)
        self.model = model

    async def generate(self, system_prompt, user_content, max_tokens):
        cfg_kwargs = {"max_output_tokens": max_tokens}
        if system_prompt:
            cfg_kwargs["system_instruction"] = system_prompt
        config = self._types.GenerateContentConfig(**cfg_kwargs)
        resp = await self.client.aio.models.generate_content(
            model=self.model,
            contents=user_content,
            config=config,
        )
        return (resp.text or "").strip()


def make_provider(company: str, api_key: str, model: str) -> Provider:
    if company == "openai":
        return OpenAIProvider(api_key, model)
    if company == "anthropic":
        return AnthropicProvider(api_key, model)
    if company == "gemini":
        return GeminiProvider(api_key, model)
    raise ValueError(f"Unknown company: {company}")


def resolve_api_key(company: str, cli_key: str | None) -> str:
    if cli_key:
        return cli_key
    for env in ENV_KEYS[company]:
        v = os.environ.get(env)
        if v:
            return v
    options = " or ".join(ENV_KEYS[company])
    print(f"ERROR: no API key for {company}. Pass --api-key or set {options}.")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Async inference
# --------------------------------------------------------------------------- #

async def run_inference(
    provider: Provider,
    task: RunTask,
    max_tokens: int,
    semaphore: asyncio.Semaphore,
    retries: int,
    retry_delay: float,
) -> tuple[RunTask, str, str, str, str, dict | None, str | None, list[dict]]:
    """
    Execute one inference task with retry-on-exception.

    Returns (task, started_at, ended_at, raw_output, status, parsed_output,
             error_text, messages).
    """
    messages = build_messages(task.system_prompt, task.scan_payload, task.doubled)

    if task.doubled:
        system_for_provider = ""
        user_for_provider = messages[0]["content"]
    else:
        system_for_provider = messages[0]["content"]
        user_for_provider = messages[1]["content"]

    async with semaphore:
        started_at = datetime.now(timezone.utc).isoformat()
        status = "complete"
        raw_output = ""
        error_text = None
        parsed_output = None
        mode_label = "doubled" if task.doubled else "normal"

        for attempt in range(retries + 1):
            try:
                raw_output = await provider.generate(
                    system_for_provider, user_for_provider, max_tokens,
                )
                parsed_output = filter_parsed_cpes(extract_cpe_json(raw_output))
                status = "complete"
                error_text = None
                break
            except Exception as e:
                error_text = str(e)
                status = "error"
                if attempt < retries:
                    delay = retry_delay * (2 ** attempt)
                    print(
                        f"  retry {attempt + 1}/{retries} in {delay:.1f}s "
                        f"(scan={task.scan_id} prompt={task.prompt_name} "
                        f"mode={mode_label}): {error_text}"
                    )
                    await asyncio.sleep(delay)

        ended_at = datetime.now(timezone.utc).isoformat()

    return (task, started_at, ended_at, raw_output, status, parsed_output,
            error_text, messages)


def write_result_to_db(
    db,
    task: RunTask,
    model_config: dict,
    started_at: str,
    ended_at: str,
    raw_output: str,
    status: str,
    parsed_output: dict | None,
    error_text: str | None,
    messages: list[dict],
) -> int:
    """Write a single result to the database. Returns run_id."""
    trial_number = db.model_runs.count_documents({
        "scan_id": task.scan_id,
        "prompt_id": task.prompt_id,
        "doubled": task.doubled,
        "model.name": model_config["name"],
    }) + 1

    run_id = next_id(db, "model_runs")
    db.model_runs.insert_one({
        "_id": run_id,
        "scan_id": task.scan_id,
        "prompt_id": task.prompt_id,
        "trial_number": trial_number,
        "doubled": task.doubled,
        "model": {
            "name":            model_config["name"],
            "version":         model_config["version"],
            "company":         model_config["company"],
            "max_tokens":      model_config["max_tokens"],
            # Sampling knobs intentionally null — provider defaults were used.
            "temperature":     None,
            "top_p":           None,
            "seed":            None,
            "guided_decoding": False,
        },
        "messages": messages,
        "raw_output": raw_output,
        "parsed_output": parsed_output,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": status,
        "error": error_text,
        "scores": [],
    })

    return run_id


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def _doubled_modes(choice: str) -> tuple[bool, ...]:
    if choice == "single":
        return (False,)
    if choice == "doubled":
        return (True,)
    return (False, True)


async def async_main(args):
    ensure_db()
    db = get_db()

    api_key = resolve_api_key(args.company, args.api_key)
    provider = make_provider(args.company, api_key, args.model)

    # Stored model name namespaces the provider to avoid collisions with local
    # checkpoints sharing a base name.
    stored_name = f"{args.company}/{args.model}"
    model_config = {
        "name":       stored_name,
        "version":    args.version,
        "company":    args.company,
        "max_tokens": args.max_tokens,
    }

    if args.scan_ids:
        scans = list(db.scans.find(
            {"_id": {"$in": args.scan_ids}}, {"_id": 1, "payload": 1}))
        missing = set(args.scan_ids) - {s["_id"] for s in scans}
        if missing:
            print(f"Warning: scan IDs not found: {sorted(missing)}")
    else:
        scans = list(db.scans.find({}, {"_id": 1, "payload": 1}).sort("_id"))

    if not scans:
        print("No scans found. Run ingest.py first.")
        sys.exit(1)

    prompts = list(db.prompts.find({}).sort("_id"))
    if not prompts:
        print("No prompts found. Run seed_prompts.py first.")
        sys.exit(1)

    doubled_modes = _doubled_modes(args.doubled)

    tasks: list[RunTask] = []
    for scan in scans:
        for prompt in prompts:
            for doubled in doubled_modes:
                tasks.append(RunTask(
                    scan_id=scan["_id"],
                    scan_payload=scan["payload"],
                    prompt_id=prompt["_id"],
                    prompt_name=prompt["prompt_name"],
                    system_prompt=prompt["prompt_text"],
                    doubled=doubled,
                ))

    n_scans = len(scans)
    n_prompts = len(prompts)
    n_tasks = len(tasks)

    modes_label = "+".join("doubled" if d else "single" for d in doubled_modes)

    print(f"\nAPI sweep configuration:")
    print(f"  Company:     {args.company}")
    print(f"  Model:       {args.model}")
    print(f"  Stored as:   {stored_name}")
    print(f"  Doubled:     {args.doubled} ({modes_label})")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Max tokens:  {args.max_tokens}")
    print(f"  Retries:     {args.retries} (initial delay {args.retry_delay}s, exp backoff)")
    print(f"  Scans:       {n_scans}")
    print(f"  Prompts:     {n_prompts}")
    print(f"  Tasks:       {n_tasks} ({n_scans} scans × {n_prompts} prompts × "
          f"{len(doubled_modes)} mode{'s' if len(doubled_modes) > 1 else ''})")
    print()

    semaphore = asyncio.Semaphore(args.concurrency)

    print(f"Starting {n_tasks} inference tasks...\n")

    coros = [
        run_inference(provider, task, args.max_tokens, semaphore,
                      args.retries, args.retry_delay)
        for task in tasks
    ]

    succeeded = 0
    failed = 0

    for i, coro in enumerate(asyncio.as_completed(coros), start=1):
        (task, started_at, ended_at, raw_output, status, parsed_output,
         error_text, messages) = await coro

        run_id = write_result_to_db(
            db, task, model_config,
            started_at, ended_at, raw_output, status, parsed_output,
            error_text, messages,
        )

        mode = "doubled" if task.doubled else "normal"

        if status == "error":
            failed += 1
            print(
                f"[{i}/{n_tasks}] ERROR scan={task.scan_id} "
                f"prompt={task.prompt_name} mode={mode}: {error_text}"
            )
        else:
            succeeded += 1
            n_cpes = 0
            if parsed_output:
                if "cpes" in parsed_output:
                    n_cpes = len(parsed_output["cpes"])
                elif "cpe" in parsed_output:
                    n_cpes = 1
            print(
                f"[{i}/{n_tasks}] OK run={run_id} "
                f"scan={task.scan_id} prompt={task.prompt_name} "
                f"mode={mode} cpes={n_cpes}"
            )

    print(f"\nDone. {succeeded} succeeded, {failed} failed, {n_tasks} total.")


def main():
    parser = argparse.ArgumentParser(
        description="Concurrent sweep of scans × prompts against a hosted LLM API."
    )
    parser.add_argument(
        "--company", required=True, choices=COMPANIES,
        help="API provider: openai | anthropic | gemini",
    )
    parser.add_argument(
        "--model", required=True,
        help="Model name as the provider expects it "
             "(e.g. 'gpt-5', 'claude-opus-4-7', 'gemini-2.5-pro').",
    )
    parser.add_argument(
        "--doubled", choices=("both", "single", "doubled"), default="both",
        help="Which prompt-doubling modes to run (default: both).",
    )
    parser.add_argument(
        "--api-key", default=None,
        help="API key. Defaults to the company's standard env var "
             "(OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY).",
    )
    parser.add_argument(
        "--concurrency", type=int, default=8,
        help="Max concurrent in-flight requests (default: 8).",
    )
    parser.add_argument(
        "--scan-ids", type=int, nargs="+",
        help="Specific scan IDs to process (default: all scans).",
    )
    parser.add_argument(
        "--version", default="",
        help="Model version string to store in the database.",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=2048,
        help="Max tokens to generate per response (default: 2048).",
    )
    parser.add_argument(
        "--retries", type=int, default=2,
        help="Retry attempts after a failure; total tries = retries + 1 (default: 2).",
    )
    parser.add_argument(
        "--retry-delay", type=float, default=2.0,
        help="Initial retry delay in seconds; doubles each attempt (default: 2.0).",
    )
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
