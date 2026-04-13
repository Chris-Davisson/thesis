# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A research thesis tool that uses LLMs to fingerprint IoT devices from nmap scan data and identify CVEs. It consists of six independent Python CLI scripts sharing a single SQLite database. The authoritative system design is in `Tech_Doc.md`.

## Running the Programs

Scripts are run manually in sequence. No build step required.

```bash
python init.py                          # First time: create DB schema
python ingest.py <nmap.xml> <device-code>  # Returns device_id and aggregated_input_id
python truth.py <device-code> <vendor> <product> <firmware> <cpes> ...  # Upsert ground truth
python setup.py <name> <model> <version> <temperature> <top_p> <seed>   # Returns experiment_id
python run.py <device_id> <experiment_id> <trial_num>
python export.py <experiment_id> [device_id]  # Outputs CSV/JSON for external analysis
```

## Architecture

**Database-first design.** All state lives in a single SQLite file. Every script calls `ensure_db()` at startup to verify the file and tables exist. `init.py` creates the schema (idempotent via `CREATE TABLE IF NOT EXISTS`). The authoritative schema is `drawSQL-mysql-export-2026-04-12.sql` (MySQL syntax; must be translated to SQLite in `init.py`).

**Pipeline flow:**
```
nmap XML → ingest.py → scan_session + scan_run + aggregated_input records
                                        ↓
setup.py → experiment record (references a prompt_id)
                        ↓               ↓
                       run.py (fetches prompt from DB by prompt_id)
                             ↓
              Single LLM call — prompt instructs reasoning then CPE output in one response
              Writes one model_run row per trial
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
- `experiments` — experimental conditions: model, version, temperature, top_p, seed, max_tokens, and a `prompt_id` FK; all four model params are intentionally kept — they apply across all three supported backends (Ollama, HuggingFace local, API); `seed` is not supported by the Claude API but is valid for Ollama and HuggingFace runs and should be stored as `NULL` for Claude runs
- `model_runs` — one row per LLM call; references `aggregated_input_id`, `experiment_id`, `prompt_id`; stores `raw_output_text`, `parsed_output_json`, `status`, `error_text`; model params duplicated here from experiment for immutable record
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
| `run.py` | `experiments`, `prompts`, `aggregated_inputs` | `model_runs` |
| `export.py` | `model_runs`, `experiments`, `aggregated_inputs`, `ground_truth`, `devices` | `scores`, CSV/JSON file |

**Note:** `prompts` rows must exist in the DB before `setup.py` is run. No dedicated script exists for loading prompts yet — insert them directly or add a `load_prompt.py`.

## Out of Scope

The system intentionally excludes: web server, REST API, frontend, live scan execution (handled by external `run_scans.py`), and statistical calculations (done externally on exported data).
