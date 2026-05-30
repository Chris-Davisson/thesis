#!/usr/bin/env python3
"""
Concurrent sweep of all scans × prompts against a local vLLM server.

Multi-model counterpart to run.py, but:
  - Talks directly to vLLM's OpenAI-compatible API (default localhost:8001)
  - Runs concurrent async requests (vLLM batches them server-side)
  - Every model + sampling parameter comes from CLI flags — config.toml is
    only consulted for the [database] block (via db.get_db / ensure_db)
  - Optional guided decoding (--guided) constrains output to a CPE JSON regex

Usage:
    python local_run.py --model "meta-llama/Llama-3.3-70B-Instruct"
    python local_run.py --model "Qwen/Qwen2.5-72B-Instruct" --guided
    python local_run.py --model "..." --concurrency 32 --port 8001
    python local_run.py --model "..." --scan-ids 1 2 3  # specific scans only
    python local_run.py --model "..." --temperature 0.7 --top-p 0.95 --seed 1
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from openai import AsyncOpenAI

from db import ensure_db, get_db, next_id


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DOUBLED_DELIMITER = "\n\n--- REPEAT ---\n\n"

# Regex pattern for guided decoding — matches JSON with "cpes" array of CPE 2.3 strings
# This constrains vLLM to output valid JSON structure
CPE_REGEX = (
    r'\{\s*"cpes"\s*:\s*\['
    r'(\s*"cpe:2\.3:[aoh]:[a-zA-Z0-9._\-~%]+:[a-zA-Z0-9._\-~%]+(:[a-zA-Z0-9._\-~%*]+){0,9}"'
    r'(\s*,\s*"cpe:2\.3:[aoh]:[a-zA-Z0-9._\-~%]+:[a-zA-Z0-9._\-~%]+(:[a-zA-Z0-9._\-~%*]+){0,9}")*'
    r')?'
    r'\s*\]\s*\}'
)


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


@dataclass
class RunResult:
    """Result from a single inference."""
    task: RunTask
    run_id: int
    status: str  # "complete" or "error"
    n_cpes: int
    error: str | None = None


# --------------------------------------------------------------------------- #
# Message building (same as run.py)
# --------------------------------------------------------------------------- #

def build_messages(system_prompt: str, scan_payload: str, doubled: bool) -> list[dict]:
    """
    Normal: standard system+user split.
    Doubled: single user message with [system, scan, DELIM, system, scan].
    """
    if doubled:
        block = f"{system_prompt}\n\n{scan_payload}"
        return [{"role": "user", "content": f"{block}{DOUBLED_DELIMITER}{block}"}]
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": scan_payload},
    ]


# --------------------------------------------------------------------------- #
# CPE extraction (same as run.py)
# --------------------------------------------------------------------------- #

def extract_cpe_json(text: str) -> dict | None:
    """Extract JSON containing CPE(s) from model output."""
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
# Async inference
# --------------------------------------------------------------------------- #

async def run_inference(
    client: AsyncOpenAI,
    task: RunTask,
    model_config: dict,
    semaphore: asyncio.Semaphore,
    retries: int,
    retry_delay: float,
) -> tuple[RunTask, str, str, str, str, dict | None, str | None, list[dict]]:
    """
    Execute a single inference task with retry-on-exception.

    Up to (retries + 1) total attempts: one initial try plus `retries` more
    on failure, with exponential backoff of retry_delay * 2**attempt seconds
    between attempts. The semaphore is held for the whole retry sequence so
    failed requests do not increase the in-flight count past --concurrency.

    Returns (task, started_at, ended_at, raw_output, status, parsed_output,
             error_text, messages).
    """
    messages = build_messages(task.system_prompt, task.scan_payload, task.doubled)

    kwargs = dict(
        model=model_config["name"],
        messages=messages,
        max_tokens=model_config["max_tokens"],
        temperature=model_config["temperature"],
        top_p=model_config["top_p"],
    )
    if model_config["seed"] is not None:
        kwargs["seed"] = model_config["seed"]
    if model_config["guided_decoding"]:
        kwargs["extra_body"] = {"guided_regex": CPE_REGEX}

    async with semaphore:
        started_at = datetime.now(timezone.utc).isoformat()
        status = "complete"
        raw_output = ""
        error_text = None
        parsed_output = None
        mode_label = "doubled" if task.doubled else "normal"

        for attempt in range(retries + 1):
            try:
                resp = await client.chat.completions.create(**kwargs)
                raw_output = resp.choices[0].message.content.strip()
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

    return (task, started_at, ended_at, raw_output, status, parsed_output, error_text, messages)


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
            "name": model_config["name"],
            "version": model_config["version"],
            "temperature": model_config["temperature"],
            "top_p": model_config["top_p"],
            "max_tokens": model_config["max_tokens"],
            "seed": model_config["seed"],
            "guided_decoding": model_config["guided_decoding"],  # <-- NEW FIELD
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

async def async_main(args):
    ensure_db()
    db = get_db()

    # Model configuration — every value comes from CLI flags
    model_config = {
        "name": args.model,
        "version": args.version,
        "temperature": args.temperature,
        "top_p": args.top_p,
        "max_tokens": args.max_tokens,
        "seed": args.seed,
        "guided_decoding": args.guided,
    }

    # Get scans
    if args.scan_ids:
        scans = list(db.scans.find({"_id": {"$in": args.scan_ids}}, {"_id": 1, "payload": 1}))
        missing = set(args.scan_ids) - {s["_id"] for s in scans}
        if missing:
            print(f"Warning: scan IDs not found: {sorted(missing)}")
    else:
        scans = list(db.scans.find({}, {"_id": 1, "payload": 1}).sort("_id"))

    if not scans:
        print("No scans found. Run ingest.py first.")
        sys.exit(1)

    # Get prompts
    prompts = list(db.prompts.find({}).sort("_id"))
    if not prompts:
        print("No prompts found. Run seed_prompts.py first.")
        sys.exit(1)

    # Build task queue: all (scan × prompt × doubled) combinations
    tasks: list[RunTask] = []
    for scan in scans:
        for prompt in prompts:
            for doubled in (False, True):
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

    print(f"\nLocal vLLM sweep configuration:")
    print(f"  Model:       {args.model}")
    print(f"  Guided:      {args.guided}")
    print(f"  Server:      http://{args.host}:{args.port}")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Temperature: {args.temperature}")
    print(f"  Top-p:       {args.top_p}")
    print(f"  Max tokens:  {args.max_tokens}")
    print(f"  Seed:        {args.seed}")
    print(f"  Retries:     {args.retries} (initial delay {args.retry_delay}s, exp backoff)")
    print(f"  Scans:       {n_scans}")
    print(f"  Prompts:     {n_prompts}")
    print(f"  Tasks:       {n_tasks} ({n_scans} scans × {n_prompts} prompts × 2 modes)")
    print()

    # Initialize async client
    client = AsyncOpenAI(
        api_key="not-needed",
        base_url=f"http://{args.host}:{args.port}/v1",
    )

    # Semaphore to limit concurrent requests
    semaphore = asyncio.Semaphore(args.concurrency)

    print(f"Starting {n_tasks} inference tasks...\n")

    # Launch all tasks concurrently
    coros = [
        run_inference(client, task, model_config, semaphore, args.retries, args.retry_delay)
        for task in tasks
    ]

    succeeded = 0
    failed = 0

    # Process results as they complete
    for i, coro in enumerate(asyncio.as_completed(coros), start=1):
        task, started_at, ended_at, raw_output, status, parsed_output, error_text, messages = await coro

        # Write to the database synchronously.
        run_id = write_result_to_db(
            db, task, model_config,
            started_at, ended_at, raw_output, status, parsed_output, error_text, messages
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

    if args.guided:
        print(f"\nNote: guided_decoding=True stored in model_runs.model.guided_decoding")


def main():
    parser = argparse.ArgumentParser(
        description="Concurrent sweep of scans × prompts against local vLLM server"
    )
    parser.add_argument(
        "--model", required=True,
        help="Model name (as loaded in vLLM, e.g. 'meta-llama/Llama-3.3-70B-Instruct')"
    )
    parser.add_argument(
        "--guided", action="store_true",
        help="Enable guided decoding (constrain output to JSON CPE format)"
    )
    parser.add_argument(
        "--host", default="localhost",
        help="vLLM server host (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=8001,
        help="vLLM server port (default: 8001)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=32,
        help="Max concurrent requests to vLLM (default: 32)"
    )
    parser.add_argument(
        "--scan-ids", type=int, nargs="+",
        help="Specific scan IDs to process (default: all scans)"
    )
    parser.add_argument(
        "--version", default="",
        help="Model version string to store in database"
    )
    parser.add_argument(
        "--temperature", type=float, default=0.0,
        help="Sampling temperature (default: 0.0)"
    )
    parser.add_argument(
        "--top-p", type=float, default=1.0,
        help="Nucleus sampling top-p (default: 1.0)"
    )
    parser.add_argument(
        "--max-tokens", type=int, default=2048,
        help="Max tokens to generate per response (default: 2048)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed forwarded to vLLM (default: 42)"
    )
    parser.add_argument(
        "--retries", type=int, default=2,
        help="Number of retry attempts after a failure; total tries = retries + 1 (default: 2)"
    )
    parser.add_argument(
        "--retry-delay", type=float, default=2.0,
        help="Initial retry delay in seconds; doubles each attempt (default: 2.0)"
    )
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
