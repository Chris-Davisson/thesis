# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A research thesis tool that uses LLMs to fingerprint IoT devices from nmap scan data and identify CVEs. It consists of six independent Python CLI scripts sharing a single SQLite database. The authoritative system design is in `Tech_Doc.md`.

## Running the Programs

Scripts are run manually in sequence. No build step required.

```bash
python init.py                                    # First time: create DB schema
python ingest.py <nmap.xml> <device-code>         # Prints aggregated_input_id on success
python truth.py <device-code> <vendor> <product> <firmware> <cpes> ...  # Upsert ground truth
python run.py <aggregated_input_id>               # Reads model/prompt from config.toml, writes model_runs row
python export.py <experiment_id> [device_id]      # (stub) Outputs CSV/JSON for external analysis
```

To test a different model or prompt against the same scan, edit `config.toml [model]` and `[prompt]` and re-run `run.py` with the same `aggregated_input_id`.

## Architecture

**Database-first design.** All state lives in a single SQLite file. Every script calls `ensure_db()` at startup to verify the file and tables exist. `init.py` creates the schema (idempotent via `CREATE TABLE IF NOT EXISTS`). The authoritative schema is `drawSQL-mysql-export-2026-04-12.sql` (MySQL syntax; must be translated to SQLite in `init.py`).

**Pipeline flow:**
```
nmap XML → ingest.py → scan_session + scan_run + aggregated_input records
                                        ↓ aggregated_input_id
                       config.toml [model] + [prompt]
                                        ↓
                                     run.py
                                        ↓
              Single LLM call — system prompt from config, user message = scan payload
              Writes one model_runs row (experiment_id/prompt_id NULL for now)
              Re-run with same ID + different config to compare models/prompts
                                        ↓
                                    export.py
                                        ↓
              Compares model_run outputs vs ground_truth → writes scores rows
              Dumps CSV/JSON for external statistical analysis
```

**Key tables:**
- `devices` — physical lab device registry; keyed by unique `device_code` (e.g. `linksys-wrt54gs`); also stores `mac`, `manufacturer`, `model`, `firmware_version`, `device_type`
- `scan_runs` — one row per nmap execution; stores `tool_name`, `tool_version`, `exit_code`, `stdout_text`, `stderr_text`, `parsed_data_json`
- `aggregated_inputs` — consolidated LLM payload; has `variant_name` and `parser_version` to track how the payload was constructed
- `prompts` — prompts are stored in the DB; each row has `prompt_name`, `prompt_version`, `prompt_text`; no `task_type` needed since there is only one stage
- `experiments` — experimental conditions: model, version, temperature, top_p, seed, max_tokens, and a `prompt_id` FK; deferred — not used by run.py yet
- `model_runs` — one row per LLM call; `aggregated_input_id` is the key FK; `experiment_id`/`prompt_id` are NULL for now; stores `raw_output_text`, `parsed_output_json`, `conversation_history_json`, `status`, `error_text`; model params stored directly here (from config.toml at call time); `seed` stored as NULL for Claude API runs
- `ground_truth` — manually entered true vendor/product/firmware/CPEs per device; has `rubric_version` and `label_status`
- `scores` — evaluation results per model_run: `exact_match`, `partial_credit_level`, `predicted_vendor`, `predicted_product`, `predicted_cpes_json`, `scorer_version`, `score_type`

**Note:** `Tech_Doc.md` describes prompts as file-based — the actual schema stores them in the `prompts` table. `Tech_Doc.md` is partially outdated; the SQL file is authoritative for schema.

## Program–Table Map

Which tables each script reads from and writes to:

| Script | Reads | Writes |
|---|---|---|
| `init.py` | — | all tables (creates schema) |
| `ingest.py` | `devices` (check if device_code exists) | `devices` (if new), `scan_sessions`, `scan_runs`, `aggregated_inputs` |
| `truth.py` | `devices` (resolve device_code → id) | `ground_truth` (upsert) |
| `setup.py` | `prompts` (validate prompt_id exists) | `experiments` |
| `run.py` | `aggregated_inputs` | `model_runs` |
| `export.py` | `model_runs`, `experiments`, `aggregated_inputs`, `ground_truth`, `devices` | `scores`, CSV/JSON file |

**Note:** `setup.py` and the experiments/prompts layer are deferred. `run.py` currently reads all config from `config.toml` and leaves `experiment_id`/`prompt_id` NULL in `model_runs`.

## Out of Scope

The system intentionally excludes: web server, REST API, frontend, live scan execution (handled by external `run_scans.py`), and statistical calculations (done externally on exported data).


## Future Work

### Hallucination detection in scoring

The scorer (`scores.py`) currently does not verify that predicted vendor:product
pairs exist in the official NIST CPE dictionary. A CPE that is structurally
valid but references a fabricated vendor — e.g., the LLM inventing
`smart_devices_inc` as a vendor name — currently scores as 0 via the no-match
path but is not distinguished from a legitimate wrong guess.

To add this:

1. Download the NVD CPE dictionary (https://nvd.nist.gov/products/cpe),
   ~1.5M entries, refreshed daily.
2. Index by (vendor, product) tuples.
3. Add a `hallucinated INTEGER` column to the `scores` table.
4. In `score_prediction()`, set `hallucinated = 1` when the predicted
   (vendor, product) pair does not appear in the dictionary.

This distinguishes "wrong but plausible guess" from "fabricated output" —
an important failure-mode signal for the thesis. Separating these two
categories means you can report both "accuracy" (how often the model is
right) and "reliability" (how often the model refuses to make up plausible-
sounding nonsense when it doesn't know).