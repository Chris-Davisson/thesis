# Thesis — LLM CPE identification pipeline

## Prereqs

- Docker Desktop running (WSL integration enabled on Windows)
- Python venv at `.venv/` with `requirements.txt` installed
- `.env` with `OPENAI_API_KEY` if using the `api` backend in `config.toml`

## One-time setup

```bash
docker compose up -d                  # start MongoDB on 127.0.0.1:27017
.venv/bin/python init.py              # create collections + indexes
.venv/bin/python seed_prompts.py      # load prompts from the PROMPTS list in seed_prompts.py
```

## Load scan data

```bash
./bootstrap.sh
```

Does two things:
1. `ingest.py` every XML under `scans/*/` → creates `devices` + `scans` docs
2. `truth.py` twice — first from concatenated per-device `scans/*/Truth.toml`, then from `config.toml` (Shodan devices)

Re-run any time scan XMLs or `Truth.toml` files change.

## Run an experiment

Configure the model + params in `config.toml` (backend, name, temperature, etc.), then:

```bash
# Inference — for each scan, sweeps every prompt in DB TWICE:
#   pass 1: normal  (doubled=false) — system + user
#   pass 2: doubled (doubled=true)  — single user message with
#           [system, scan, ---REPEAT---, system, scan]
# So each invocation writes 2 × len(prompts) model_runs docs per scan.
for id in $(.venv/bin/python -c "from db import get_db; [print(s['_id']) for s in get_db().scans.find({}, {'_id':1})]"); do
  .venv/bin/python run.py "$id"
done

# Synthesize nmap baseline runs (one per scan, scored like any model).
# Baseline rows always carry doubled=false.
.venv/bin/python baseline.py --all

# Score every unscored model_run against its device's ground truth.
.venv/bin/python scores.py --all

# Export to xlsx — 5 sheets, all split by the `doubled` column so
# normal and doubled runs never pool into the same aggregate row.
.venv/bin/python export.py
```

Shell wrappers `run_all.sh` / `run_all.ps1` do the scan-id loop for you.

To run multiple models or configs, change `config.toml` between `run.py` invocations — each response becomes a new `model_runs` doc, so previous runs are preserved. `trial_number` auto-increments per `(scan, prompt, doubled, model)` tuple, so repeat invocations accumulate trials for variance analysis. `scores.py --all` only scores runs that don't have scores yet.

## Full reset

When scan data, truth, or prompts need a clean slate:

```bash
# Drop DB
.venv/bin/python -c "from db import load_config; from pymongo import MongoClient; c = load_config()['database']; MongoClient(c['uri']).drop_database(c['name'])"

# Rebuild
.venv/bin/python init.py
.venv/bin/python seed_prompts.py
./bootstrap.sh
```

## Single-scan operations

Useful for debugging or re-running one scan:

```bash
.venv/bin/python ingest.py <xml_file> <device_code>
.venv/bin/python run.py <scan_id>                   # does both normal + doubled passes
.venv/bin/python baseline.py <scan_id>
.venv/bin/python baseline.py --rebuild <scan_id>    # replace existing baseline
.venv/bin/python scores.py <model_run_id>
.venv/bin/python scores.py --rescore <model_run_id>
```

## Layout

| Collection   | What's in it                                                          |
|--------------|-----------------------------------------------------------------------|
| `devices`    | One doc per physical/Shodan device. Embeds `ground_truth` sub-doc.    |
| `scans`      | One doc per nmap XML. Contains raw XML, parsed host, and LLM payload. |
| `prompts`    | One doc per `(name, version)`. Immutable once referenced by a run.    |
| `model_runs` | One doc per `(scan, prompt, model, doubled, trial)` response. Embeds `scores` array. |
| `counters`   | `_id` generator. Don't touch.                                         |

### Key `model_runs` fields

| Field          | What it means                                                       |
|----------------|---------------------------------------------------------------------|
| `scan_id`      | Which scan's payload was fed in.                                    |
| `prompt_id`    | Which prompt was used (`null` for `nmap` baseline rows).            |
| `doubled`      | `false` = normal system+user; `true` = prompt-sandwich single user. |
| `trial_number` | 1-based counter per `(scan, prompt, doubled, model.name)`. Repeat `run.py` invocations produce trial 2, 3, … |
| `model.name`   | `qwen...`, `gpt-...`, or `nmap` for the baseline rows.              |
| `parsed_output`| `{"cpes": [...]}` extracted from `raw_output`. Used by scorer.      |
| `scores`       | Array of per-prediction scoring rows; populated by `scores.py`.     |

## Supported backends

`config.toml` `[model].backend` accepts:

- `ollama` — local via Ollama (uses `ollama_host`)
- `vllm` — local via vLLM's OpenAI-compatible API (uses `vllm_host`; `/v1` appended automatically)
- `huggingface` — local via transformers pipeline (no host)
- `api` — OpenAI API (uses `api_endpoint`; empty means OpenAI default; reads `OPENAI_API_KEY` from `.env`)
- `cli` — any locally-installed CLI tool that takes a prompt on stdin and prints the response. Configure via `cli_command` (full argv vector). Example: `cli_command = ["claude", "-p", "--model", "claude-opus-4-7"]` for Claude Code. Sampling args (`temperature`/`top_p`/`seed`/`max_tokens`) are not forwarded — bake them into `cli_command` if the tool supports them.
