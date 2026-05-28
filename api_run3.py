#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from db import ensure_db, get_db, next_id

COMPANIES = ("openai", "anthropic", "gemini")

ENV_KEYS = {
    "openai":    ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini":    ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

DOUBLED_DELIMITER = "\n\n--- REPEAT ---\n\n"

@dataclass
class RunTask:
    scan_id: int
    scan_payload: str
    prompt_id: int
    prompt_name: str
    system_prompt: str

def build_messages(system_prompt: str, scan_payload: str) -> list[dict]:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": scan_payload},
    ]

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

def extract_cpe_json(text: str) -> dict | None:
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
# Synchronous Provider Clients
# --------------------------------------------------------------------------- #

class OpenAIProvider:
    def __init__(self, api_key: str, model: str):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(self, system_prompt, user_content, max_tokens):
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ] if system_prompt else [{"role": "user", "content": user_content}]
        
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_completion_tokens=max_tokens,
        )
        return (resp.choices[0].message.content or "").strip()


class AnthropicProvider:
    def __init__(self, api_key: str, model: str):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=api_key)
        self.model = model

    def generate(self, system_prompt, user_content, max_tokens):
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": user_content}],
        )
        if system_prompt:
            kwargs["system"] = system_prompt
            
        resp = self.client.messages.create(**kwargs)
        return "".join(getattr(b, "text", "") for b in (resp.content or [])).strip()


class GeminiProvider:
    def __init__(self, api_key: str, model: str):
        from google import genai
        from google.genai import types
        self._types = types
        self.client = genai.Client(api_key=api_key)
        self.model = model

    def generate(self, system_prompt, user_content, max_tokens):
        cfg_kwargs = {"max_output_tokens": max_tokens}
        if system_prompt:
            cfg_kwargs["system_instruction"] = system_prompt
            
        config = self._types.GenerateContentConfig(**cfg_kwargs)
        resp = self.client.models.generate_content(
            model=self.model,
            contents=user_content,
            config=config,
        )
        return (resp.text or "").strip()


def make_provider(company: str, api_key: str, model: str):
    if company == "openai":
        return OpenAIProvider(api_key, model)
    if company == "anthropic":
        return AnthropicProvider(api_key, model)
    if company == "gemini":
        return GeminiProvider(api_key, model)
    raise ValueError(f"Unknown company: {company}")


# --------------------------------------------------------------------------- #
# Database Writing
# --------------------------------------------------------------------------- #

def write_result_to_db(
    db, task: RunTask, model_config: dict, started_at: str, ended_at: str,
    raw_output: str, status: str, parsed_output: dict | None,
    error_text: str | None, messages: list[dict],
) -> int:
    trial_number = db.model_runs.count_documents({
        "scan_id": task.scan_id,
        "prompt_id": task.prompt_id,
        "doubled": False,
        "model.name": model_config["name"],
    }) + 1

    run_id = next_id(db, "model_runs")
    db.model_runs.insert_one({
        "_id": run_id,
        "scan_id": task.scan_id,
        "prompt_id": task.prompt_id,
        "trial_number": trial_number,
        "doubled": False,
        "model": {
            "name":            model_config["name"],
            "version":         model_config["version"],
            "company":         model_config["company"],
            "max_tokens":      model_config["max_tokens"],
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

def main():
    parser = argparse.ArgumentParser(description="Single-shot or sweep inference against a hosted LLM API (Resumable).")
    parser.add_argument("--company", required=True, choices=COMPANIES)
    parser.add_argument("--model", required=True)
    parser.add_argument("--scan-id", type=int, help="Specific scan ID to process (omit for all)")
    parser.add_argument("--prompt-id", type=int, help="Specific prompt ID to use (omit for all)")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--version", default="")
    parser.add_argument("--max-tokens", type=int, default=2048)
    args = parser.parse_args()

    ensure_db()
    db = get_db()
    
    # Initialize the synchronous provider
    api_key = resolve_api_key(args.company, args.api_key)
    provider = make_provider(args.company, api_key, args.model)
    stored_name = f"{args.company}/{args.model}"
    model_config = {
        "name":       stored_name,
        "version":    args.version,
        "company":    args.company,
        "max_tokens": args.max_tokens,
    }

    # Fetch Scans
    if args.scan_id:
        scans = list(db.scans.find({"_id": args.scan_id}, {"_id": 1, "payload": 1}))
        if not scans:
            print(f"Scan {args.scan_id} not found.")
            sys.exit(1)
    else:
        scans = list(db.scans.find({}, {"_id": 1, "payload": 1}).sort("_id"))

    # Fetch Prompts
    if args.prompt_id:
        prompts = list(db.prompts.find({"_id": args.prompt_id}))
        if not prompts:
            print(f"Prompt {args.prompt_id} not found.")
            sys.exit(1)
    else:
        prompts = list(db.prompts.find({}).sort("_id"))

    if not scans or not prompts:
        print("No scans or prompts found in database.")
        sys.exit(1)

    tasks = []
    for s in scans:
        for p in prompts:
            tasks.append(RunTask(
                scan_id=s["_id"],
                scan_payload=s["payload"],
                prompt_id=p["_id"],
                prompt_name=p["prompt_name"],
                system_prompt=p["prompt_text"],
            ))

    n_tasks = len(tasks)
    print(f"\nStarting {n_tasks} sequential inference tasks...")
    print(f"  Company:    {args.company}")
    print(f"  Model:      {args.model}\n")

    for i, task in enumerate(tasks, start=1):
        # Check if run already exists to skip
        existing_run = db.model_runs.find_one({
            "scan_id": task.scan_id,
            "prompt_id": task.prompt_id,
            "doubled": False,
            "model.name": model_config["name"],
        })
        
        if existing_run:
            print(f"[{i}/{n_tasks}] SKIP scan={task.scan_id} prompt={task.prompt_name} (already exists: run={existing_run['_id']})")
            continue

        messages = build_messages(task.system_prompt, task.scan_payload)
        started_at = datetime.now(timezone.utc).isoformat()
        status = "complete"
        raw_output = ""
        error_text = None
        parsed_output = None

        try:
            # We use messages[0] for system and messages[1] for user
            raw_output = provider.generate(messages[0]["content"], messages[1]["content"], args.max_tokens)
            parsed_output = filter_parsed_cpes(extract_cpe_json(raw_output))
        except Exception as e:
            error_text = str(e)
            status = "error"

        ended_at = datetime.now(timezone.utc).isoformat()

        run_id = write_result_to_db(
            db, task, model_config, started_at, ended_at, raw_output,
            status, parsed_output, error_text, messages,
        )

        if status == "error":
            print(f"[{i}/{n_tasks}] ERROR scan={task.scan_id} prompt={task.prompt_name}: {error_text}")
        else:
            n_cpes = 0
            if parsed_output:
                if "cpes" in parsed_output:
                    n_cpes = len(parsed_output["cpes"])
                elif "cpe" in parsed_output:
                    n_cpes = 1
            print(f"[{i}/{n_tasks}] OK run={run_id} scan={task.scan_id} prompt={task.prompt_name} cpes={n_cpes}")

    print("\nDone.")


if __name__ == "__main__":
    main()