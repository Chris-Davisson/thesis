#!/usr/bin/env python3
"""
ollama_cloud_run.py — Async sweep of (scans × prompts × doubled) against
Ollama-hosted models (cloud or local), with retry-on-empty-body.

Purpose: re-run Ollama Cloud models (kimi-k2.6:cloud, qwen3.5:cloud, …) that
returned empty bodies for most of their original sweep. The original
sequential runner could not distinguish "server timed out and returned
empty" from "model abstained," so empty bodies were stored without
classification. This script:

  - Sends concurrent requests (default 8) against the local Ollama endpoint,
    which forwards :cloud model traffic to ollama.com.
  - Retries on HTTP error AND on short responses (configurable
    threshold; default <8 chars).
  - Supports targeting a subset of (scan, prompt, doubled) tuples that were
    previously empty, instead of re-running the entire sweep.
  - Writes to the same model_runs schema as run.py / local_run.py so
    score.py processes the new rows.

Usage:
    # Re-run only previously-empty (scan, prompt, doubled) combinations for kimi:
    python ollama_cloud_run.py --model kimi-k2.6:cloud --only-empty

    # Multiple models:
    python ollama_cloud_run.py --model kimi-k2.6:cloud --model qwen3.5:cloud --only-empty

    # Full re-sweep, higher concurrency:
    python ollama_cloud_run.py --model kimi-k2.6:cloud --concurrency 16

    # Delete the previous empty runs first, then write replacement ones (instead of
    # accumulating trials):
    python ollama_cloud_run.py --model kimi-k2.6:cloud --only-empty --replace-empty

    # Specific scans only:
    python ollama_cloud_run.py --model kimi-k2.6:cloud --scan-ids 1 2 3 --only-empty
"""

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from ollama import AsyncClient

from db import ensure_db, get_db, next_id


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DOUBLED_DELIMITER = "\n\n--- REPEAT ---\n\n"

# Anything shorter than this in raw_output is treated as an incomplete
# response and retried. Tune via --min-output-chars.
DEFAULT_MIN_OUTPUT_CHARS = 8


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class RunTask:
    scan_id: int
    scan_payload: str
    prompt_id: int
    prompt_name: str
    system_prompt: str
    doubled: bool


# --------------------------------------------------------------------------- #
# Message building (same construction as run.py / local_run.py)
# --------------------------------------------------------------------------- #

def build_messages(system_prompt: str, scan_payload: str, doubled: bool) -> list[dict]:
    if doubled:
        block = f"{system_prompt}\n\n{scan_payload}"
        return [{"role": "user", "content": f"{block}{DOUBLED_DELIMITER}{block}"}]
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": scan_payload},
    ]


# --------------------------------------------------------------------------- #
# CPE extraction (matches local_run.py — keep in sync until cpe_parsing.py exists)
# --------------------------------------------------------------------------- #

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
        if validate_cpe(parsed["cpe"]):
            return {"cpe": parsed["cpe"]}
        return None
    return parsed


# --------------------------------------------------------------------------- #
# Response parsing (defensive across ollama library versions)
# --------------------------------------------------------------------------- #

def _extract_content_and_thinking(resp) -> tuple[str, str]:
    """
    Handle both dict (older ollama) and ChatResponse pydantic object (newer).
    Returns (content, thinking). Either may be empty string.
    """
    msg = None
    if hasattr(resp, "message"):
        msg = resp.message
    elif isinstance(resp, dict):
        msg = resp.get("message")
    if msg is None:
        return "", ""

    if isinstance(msg, dict):
        return (msg.get("content") or ""), (msg.get("thinking") or "")
    # pydantic Message object
    return (getattr(msg, "content", "") or ""), (getattr(msg, "thinking", "") or "")


# --------------------------------------------------------------------------- #
# Async inference with retry-on-empty
# --------------------------------------------------------------------------- #

async def run_one(
    client: AsyncClient,
    task: RunTask,
    model_name: str,
    model_config: dict,
    semaphore: asyncio.Semaphore,
    retries: int,
    retry_delay: float,
    min_output_chars: int,
    think: bool,
):
    """One inference with retry. Retries on HTTP error AND on too-short body."""
    messages = build_messages(task.system_prompt, task.scan_payload, task.doubled)

    options = {
        "temperature": model_config["temperature"],
        "top_p":       model_config["top_p"],
        "num_predict": model_config["max_tokens"],
    }
    if model_config["seed"] is not None:
        options["seed"] = model_config["seed"]

    chat_kwargs = dict(
        model=model_name,
        messages=messages,
        options=options,
        stream=False,
    )
    # `think` is a top-level chat param on ollama-python >= 0.4. Models without
    # reasoning support silently ignore it. Passing False on a
    # reasoning model (kimi-k2.6, qwen3.5, …) prevents the model from spending
    # its token budget on internal thinking and leaving content empty.
    chat_kwargs["think"] = think

    async with semaphore:
        started_at = datetime.now(timezone.utc).isoformat()
        raw_output = ""
        thinking_text = ""
        status = "complete"
        error_text = None
        parsed_output = None
        mode = "doubled" if task.doubled else "normal"

        for attempt in range(retries + 1):
            try:
                resp = await client.chat(**chat_kwargs)
                content, thinking_text = _extract_content_and_thinking(resp)
                raw_output = content.strip()
                if len(raw_output) < min_output_chars:
                    # Server returned 200 but the body is too short to be a
                    # real answer. Most common cause: the model is a reasoning
                    # model that consumed its budget on thinking. A retry still
                    # covers transient empty responses.
                    n_think = len(thinking_text or "")
                    error_text = f"empty_body (content={len(raw_output)} chars, thinking={n_think} chars)"
                    status = "error"
                    if attempt < retries:
                        delay = retry_delay * (2 ** attempt)
                        print(
                            f"  retry {attempt + 1}/{retries} in {delay:.1f}s "
                            f"(empty body; scan={task.scan_id} prompt={task.prompt_name} mode={mode}; "
                            f"thinking_chars={n_think})"
                        )
                        await asyncio.sleep(delay)
                        continue
                else:
                    parsed_output = filter_parsed_cpes(extract_cpe_json(raw_output))
                    status = "complete"
                    error_text = None
                    break
            except TypeError as e:
                # Older ollama-python without `think` kw — retry without it.
                if "think" in str(e) and "think" in chat_kwargs:
                    chat_kwargs.pop("think", None)
                    print("  (ollama-python lacks 'think' kwarg; retrying without it)")
                    continue
                error_text = str(e)
                status = "error"
                break
            except Exception as e:
                error_text = str(e)
                status = "error"
                if attempt < retries:
                    delay = retry_delay * (2 ** attempt)
                    print(
                        f"  retry {attempt + 1}/{retries} in {delay:.1f}s "
                        f"(scan={task.scan_id} prompt={task.prompt_name} mode={mode}): {error_text}"
                    )
                    await asyncio.sleep(delay)

        ended_at = datetime.now(timezone.utc).isoformat()

    return task, started_at, ended_at, raw_output, status, parsed_output, error_text, messages, thinking_text


# --------------------------------------------------------------------------- #
# DB writes
# --------------------------------------------------------------------------- #

def write_result_to_db(
    db,
    task: RunTask,
    model_name: str,
    model_config: dict,
    started_at: str,
    ended_at: str,
    raw_output: str,
    status: str,
    parsed_output: dict | None,
    error_text: str | None,
    messages: list[dict],
    thinking_text: str = "",
) -> int:
    trial_number = db.model_runs.count_documents({
        "scan_id":    task.scan_id,
        "prompt_id":  task.prompt_id,
        "doubled":    task.doubled,
        "model.name": model_name,
    }) + 1

    doc = {
        "_id":          next_id(db, "model_runs"),
        "scan_id":      task.scan_id,
        "prompt_id":    task.prompt_id,
        "trial_number": trial_number,
        "doubled":      task.doubled,
        "model": {
            "name":            model_name,
            "version":         model_config["version"],
            "temperature":     model_config["temperature"],
            "top_p":           model_config["top_p"],
            "max_tokens":      model_config["max_tokens"],
            "seed":            model_config["seed"],
            "guided_decoding": False,
            "think":           model_config.get("think", True),
        },
        "messages":      messages,
        "raw_output":    raw_output,
        "parsed_output": parsed_output,
        "started_at":    started_at,
        "ended_at":      ended_at,
        "status":        status,
        "error":         error_text,
        "scores":        [],
    }
    if thinking_text:
        doc["thinking"] = thinking_text
    db.model_runs.insert_one(doc)
    return doc["_id"]


# --------------------------------------------------------------------------- #
# Task selection
# --------------------------------------------------------------------------- #

def find_empty_tuples(db, model_name: str, min_chars: int) -> set[tuple[int, int, bool]]:
    """Return {(scan_id, prompt_id, doubled)} where this model has at least
    one prior run whose raw_output is shorter than min_chars."""
    cursor = db.model_runs.find(
        {"model.name": model_name},
        {"scan_id": 1, "prompt_id": 1, "doubled": 1, "raw_output": 1},
    )
    empties = set()
    for r in cursor:
        ro = r.get("raw_output") or ""
        if len(ro) < min_chars:
            empties.add((r["scan_id"], r.get("prompt_id"), bool(r.get("doubled"))))
    return empties


def find_existing_tuples(db, model_name: str) -> set[tuple[int, int, bool]]:
    """Return {(scan_id, prompt_id, doubled)} that this model has ANY run for."""
    cursor = db.model_runs.find(
        {"model.name": model_name},
        {"scan_id": 1, "prompt_id": 1, "doubled": 1},
    )
    return {(r["scan_id"], r.get("prompt_id"), bool(r.get("doubled"))) for r in cursor}


def delete_empty_runs(db, model_name: str, min_chars: int) -> int:
    """Delete prior runs for model_name whose raw_output is empty/short. Returns count."""
    cursor = db.model_runs.find(
        {"model.name": model_name},
        {"_id": 1, "raw_output": 1},
    )
    to_delete = [r["_id"] for r in cursor if len((r.get("raw_output") or "")) < min_chars]
    if to_delete:
        db.model_runs.delete_many({"_id": {"$in": to_delete}})
    return len(to_delete)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

async def sweep_model(args, db, scans, prompts, model_name: str, model_config: dict, client: AsyncClient):
    """Run the sweep for one model. Returns (succeeded, failed)."""

    # Build the candidate task universe
    all_tuples = set()
    for scan in scans:
        for prompt in prompts:
            for doubled in (False, True):
                all_tuples.add((scan["_id"], prompt["_id"], doubled))

    # Select tuples to run
    if args.only_empty:
        target = find_empty_tuples(db, model_name, args.min_output_chars)
        target &= all_tuples
        n_existing_empties = len(target)
        print(f"  [{model_name}] --only-empty: {n_existing_empties} prior empty (scan, prompt, doubled) tuples to retry.")
    elif args.skip_existing:
        existing = find_existing_tuples(db, model_name)
        target = all_tuples - existing
        print(f"  [{model_name}] --skip-existing: {len(target)} of {len(all_tuples)} tuples have no prior run.")
    else:
        target = all_tuples
        print(f"  [{model_name}] full sweep: {len(target)} tuples.")

    if args.replace_empty:
        deleted = delete_empty_runs(db, model_name, args.min_output_chars)
        print(f"  [{model_name}] --replace-empty: deleted {deleted} prior empty runs.")

    if not target:
        print(f"  [{model_name}] nothing to do.")
        return 0, 0

    # Build the task list in stable order
    scan_payloads = {s["_id"]: s["payload"] for s in scans}
    prompt_objs   = {p["_id"]: p for p in prompts}

    tasks = []
    for scan_id, prompt_id, doubled in sorted(target):
        tasks.append(RunTask(
            scan_id=scan_id,
            scan_payload=scan_payloads[scan_id],
            prompt_id=prompt_id,
            prompt_name=prompt_objs[prompt_id]["prompt_name"],
            system_prompt=prompt_objs[prompt_id]["prompt_text"],
            doubled=doubled,
        ))

    semaphore = asyncio.Semaphore(args.concurrency)

    coros = [
        run_one(client, t, model_name, model_config, semaphore,
                args.retries, args.retry_delay, args.min_output_chars,
                think=args.think)
        for t in tasks
    ]

    succeeded = 0
    failed    = 0
    n_total   = len(coros)
    started   = datetime.now(timezone.utc)

    for i, coro in enumerate(asyncio.as_completed(coros), start=1):
        task, started_at, ended_at, raw_output, status, parsed_output, error_text, messages, thinking_text = await coro

        write_result_to_db(
            db, task, model_name, model_config,
            started_at, ended_at, raw_output, status, parsed_output, error_text, messages,
            thinking_text=thinking_text,
        )

        if status == "complete":
            succeeded += 1
            n_cpes = len((parsed_output or {}).get("cpes", []) or []) if parsed_output else 0
            tag = f"{n_cpes} cpe(s)" if n_cpes else "no cpes parsed"
            print(f"[{i:>4}/{n_total}] {model_name} scan={task.scan_id} "
                  f"prompt={task.prompt_name} {'D' if task.doubled else 'N'}  "
                  f"OK   {tag}  ({len(raw_output)} chars)")
        else:
            failed += 1
            print(f"[{i:>4}/{n_total}] {model_name} scan={task.scan_id} "
                  f"prompt={task.prompt_name} {'D' if task.doubled else 'N'}  "
                  f"FAIL {error_text!r}")

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    print(f"\n  [{model_name}] done in {elapsed:.1f}s. "
          f"succeeded={succeeded} failed={failed} "
          f"({succeeded / max(elapsed, 1e-6):.2f} req/s sustained)")
    return succeeded, failed


async def async_main(args):
    ensure_db()
    db = get_db()

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

    prompts = list(db.prompts.find({}).sort("_id"))
    if not prompts:
        print("No prompts found. Run seed_prompts.py first.")
        sys.exit(1)

    model_config = {
        "version":     args.version,
        "temperature": args.temperature,
        "top_p":       args.top_p,
        "max_tokens":  args.max_tokens,
        "seed":        args.seed,
        "think":       args.think,
    }

    # Ollama AsyncClient. host=None uses the OLLAMA_HOST env var if set,
    # otherwise localhost:11434. For Cloud usage, set OLLAMA_HOST to
    # https://ollama.com (or leave local and let your local Ollama forward
    # :cloud model requests upstream).
    client = AsyncClient(host=args.host) if args.host else AsyncClient()

    print(f"\nOllama async sweep configuration:")
    print(f"  Models:      {args.model}")
    print(f"  Host:        {args.host or os.environ.get('OLLAMA_HOST', 'http://localhost:11434 (default)')}")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Temperature: {args.temperature}")
    print(f"  Top-p:       {args.top_p}")
    print(f"  Max tokens:  {args.max_tokens}")
    print(f"  Seed:        {args.seed}")
    print(f"  Retries:     {args.retries} (initial delay {args.retry_delay}s, exp backoff)")
    print(f"  Empty threshold: <{args.min_output_chars} chars triggers retry")
    print(f"  Internal thinking: {'enabled' if args.think else 'DISABLED (--no-think)'}")
    print(f"  Mode:        " + (
        "only-empty"  if args.only_empty else
        "skip-existing" if args.skip_existing else
        "full"
    ) + (" + replace-empty" if args.replace_empty else ""))
    print(f"  Scans:       {len(scans)}")
    print(f"  Prompts:     {len(prompts)}")
    print()

    grand_succeeded = 0
    grand_failed    = 0

    for model_name in args.model:
        print(f"\n=== {model_name} ===")
        s, f = await sweep_model(args, db, scans, prompts, model_name, model_config, client)
        grand_succeeded += s
        grand_failed    += f

    print(f"\nAll done. {grand_succeeded} succeeded, {grand_failed} failed across {len(args.model)} model(s).")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", action="append", required=True,
                   help="Ollama model name. Repeat for multiple models. "
                        "Example: --model kimi-k2.6:cloud --model qwen3.5:cloud")
    p.add_argument("--host", default=None,
                   help="Ollama host URL. Defaults to OLLAMA_HOST env or http://localhost:11434.")
    p.add_argument("--concurrency", type=int, default=8,
                   help="Max in-flight requests per model (default: 8)")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--top-p",       type=float, default=1.0)
    p.add_argument("--seed",        type=int,   default=42)
    p.add_argument("--max-tokens",  type=int,   default=2048)
    p.add_argument("--version",     default="")
    p.add_argument("--retries",     type=int,   default=3,
                   help="Retries per task on error or empty body (default: 3)")
    p.add_argument("--retry-delay", type=float, default=2.0,
                   help="Initial retry delay in seconds, exponentially backed off (default: 2.0)")
    p.add_argument("--min-output-chars", type=int, default=DEFAULT_MIN_OUTPUT_CHARS,
                   help=f"Outputs shorter than this trigger a retry (default: {DEFAULT_MIN_OUTPUT_CHARS}). "
                        "Set to 0 to disable empty-body retry.")
    p.add_argument("--scan-ids", type=int, nargs="*",
                   help="Restrict to specific scan IDs.")
    p.add_argument("--no-think", dest="think", action="store_false", default=True,
                   help="Disable internal reasoning for reasoning-capable models "
                        "(kimi-k2.6, qwen3.5, etc.). Reasoning models can spend their "
                        "entire token budget on internal thinking and leave the user-"
                        "visible content empty. Strongly recommended when targeting "
                        "these models for batch sweeps.")

    target_group = p.add_mutually_exclusive_group()
    target_group.add_argument("--only-empty", action="store_true",
                              help="Only re-run (scan, prompt, doubled) tuples that previously produced empty bodies.")
    target_group.add_argument("--skip-existing", action="store_true",
                              help="Skip (scan, prompt, doubled) tuples that already have any run for this model.")

    p.add_argument("--replace-empty", action="store_true",
                   help="Before running, delete this model's prior empty runs from the DB so the matrix doesn't accumulate empties.")

    args = p.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
