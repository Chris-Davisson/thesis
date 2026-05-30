# LLM CPE Identification Pipeline

Code for the thesis *Evaluating LLMs for CPE Identification in IoT Reconnaissance*. It
runs Nmap scans through a set of language models, asks each one to produce CPE strings
identifying the device, and scores those predictions against per-device ground truth.

The pipeline is a handful of command-line scripts that hand state to each other through
one MongoDB database. There's no orchestrator and nothing held in memory between steps,
so any stage can be re-run on its own. That matters because inference takes days and
scoring takes seconds; you don't want a rubric tweak to force a week of re-runs.

## Pipeline at a glance

```
run_scans.py        nmap → scans/<ip>_<ts>/*.xml         collect raw scans
        │
        ▼
ingest.py           XML → devices + scans docs           parse, build the LLM payload
truth.py            Truth.toml → devices.ground_truth    load accepted CPEs
seed_prompts.py     PROMPTS list → prompts docs          load the 7 prompts
        │
        ▼
local_run.py        vLLM sweep      ─┐
api_run.py          frontier API    ─┼─→ model_runs docs (raw + parsed CPEs)
ollama_cloud_run.py Ollama Cloud    ─┤
run.py              single scan     ─┘
baseline.py         nmap-native CPEs ──→ model_runs (model.name="nmap")
        │
        ▼
score.py            score each run against ground truth, write the scores[] array
        │
        ▼
analyze.py          PNG plots + HTML report
export_thesis_data.py   frozen chart-ready .xlsx          (see Analysis, below)
```

## Prerequisites

- Docker for MongoDB, or any MongoDB reachable at the URI in `config.toml`
- Python 3.11 or newer (the code relies on stdlib `tomllib`)
- A virtual environment with `requirements.txt` installed
- `nmap` on `PATH`, if you're collecting scans yourself
- For inference, whatever backends you actually use: a vLLM server, an Ollama host,
  and/or API keys in `.env` (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`)

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
docker compose up -d          # MongoDB on 127.0.0.1:27017
```

## Database setup

Create the collections and indexes, then load scans, ground truth, and prompts:

```bash
.venv/bin/python init.py                 # collections + indexes, idempotent
./scripts/bootstrap_db.sh                 # ingest scans, load truth, seed prompts
```

`bootstrap_db.sh` (use `bootstrap_db.ps1` on Windows) walks `scans/<device>/<run>/*.xml`,
runs `ingest.py` on each XML under its device-code directory, concatenates the per-device
`Truth.toml` files, runs `truth.py`, and seeds the prompts. Run it again whenever the scan
XMLs or `Truth.toml` files change. It's idempotent.

To collect scans first (needs root for `-O` and the UDP scans):

```bash
.venv/bin/python run_scans.py 192.168.1.1 [more IPs...]
```

## Running inference

Every runner writes the same `model_runs` document shape no matter which backend produced
it, so `score.py` and `analyze.py` don't care where a row came from. Each runner sweeps
every scan against every prompt, in both the normal and doubled variants where the backend
supports it. Nothing gets overwritten: `trial_number` counts up per
`(scan, prompt, doubled, model)` tuple, so re-running just adds trials.

Local vLLM, the main local arm:

```bash
.venv/bin/python local_run.py --model "Qwen/Qwen3-8B-Instruct" --port 8001
.venv/bin/python local_run.py --model "..." --guided            # constrained decoding
```

Trial 1 is the plain unguided run. `scripts/local_run_lazy.ps1` runs trials 2 through 4
(`--guided`, then `--guided --temperature 0.7`, then the same plus `--seed 1`). The guided
trials stay in the database but don't feed the primary results; the discussion chapter
explains why.

Frontier APIs (OpenAI, Anthropic, Gemini):

```bash
.venv/bin/python api_run.py --company openai    --model gpt-5.5
.venv/bin/python api_run.py --company anthropic --model claude-opus-4-7 --doubled single
.venv/bin/python api_run.py --company gemini    --model gemini-3.1-pro-preview
```

Sampling parameters are deliberately left at provider defaults here, so the numbers reflect
what an ordinary API caller would get. The doubled variant ran for Gemini only; pass
`--doubled single` for OpenAI and Anthropic.

Ollama Cloud, which retries when the server hands back an empty body:

```bash
.venv/bin/python ollama_cloud_run.py --model kimi-k2.6:cloud --no-think
.venv/bin/python ollama_cloud_run.py --model some-model:cloud --only-empty   # retry empties
```

Single scan, driven by `config.toml` (handy for debugging or config-swap sweeps):

```bash
.venv/bin/python run.py <scan_id>                 # both normal + doubled passes
.venv/bin/python run.py <scan_id> --model qwen3.5:cloud
```

`run.py` reads the model and backend from `config.toml` and handles the `ollama`, `vllm`,
`huggingface`, `api`, and `cli` backends. The `scripts/sweep_*` wrappers loop it over every
scan for one or more models.

Baseline, with no model in the loop:

```bash
.venv/bin/python baseline.py --all
```

`baseline.py` pulls the CPEs Nmap emitted on its own out of the scan XML and stores them as
`model.name="nmap"` rows. They go through the same scorer as everything else, so the rest
of the results have a no-LLM floor to sit against.

## Scoring

```bash
.venv/bin/python score.py                  # score every complete run
.venv/bin/python score.py --unscored-only  # skip runs that already have scores
.venv/bin/python score.py --scan-id 5      # one scan only
```

`score.py` is the scorer of record. It lowercases the prediction and each accepted CPE,
pads both to the 13 CPE 2.3 fields, and assigns a tier:

| Tier      | Weight |
|-----------|--------|
| `exact`   | 1.00   |
| `partial` | 0.50   |
| `related` | 0.25   |
| `none`    | 0.00   |

A prediction matches an accepted CPE when every non-wildcard field in the accepted entry
equals the prediction. When several match, the highest tier wins. The per-field flags
(`part`, `vendor`, `product`, `version`) are overlap diagnostics, not a success rate: a
prediction can land in tier `none` and still have the right vendor field, so read those
columns as field agreement rather than "the model got it." Re-running replaces existing
scores, which is what makes a rubric change cheap.

## Analysis

```bash
.venv/bin/python analyze.py                       # PNGs + self-contained report.html
.venv/bin/python analyze.py --output exports/run1
```

`analyze.py` joins `model_runs`, scores, scans, devices, and prompts into one DataFrame and
writes roughly 25 plots, an HTML report, and a Markdown context document under `exports/`.

The thesis tables and figures come from `export_thesis_data.py`, which imports from
`analyze.py` and applies the Chapter 5 experimental-matrix filter (trial 1 only, excluded
models and devices) before it aggregates. That script and its figure generators currently
live in `archive/`; see the note at the end.

## Full reset

```bash
# Drop the database
.venv/bin/python -c "from db import load_config; from pymongo import MongoClient; \
c = load_config()['database']; MongoClient(c['uri']).drop_database(c['name'])"

# Rebuild from source-controlled artifacts
.venv/bin/python init.py
./scripts/bootstrap_db.sh
```

The whole database can be rebuilt from what's in version control: the scan XML under
`scans/`, the per-device `Truth.toml` files, the prompts in `seed_prompts.py`, and the scan
suites in `config.toml`. The reset runs in under a minute. Repopulating `model_runs` does
not; the full vLLM sweep is about a week on the hardware this was built on.

## MongoDB schema

| Collection   | Contents                                                                 |
|--------------|--------------------------------------------------------------------------|
| `devices`    | One doc per device. Holds the `ground_truth` sub-document.               |
| `scans`      | One doc per Nmap XML: raw XML, parsed host, and the plaintext LLM payload.|
| `prompts`    | One doc per `(prompt_name, prompt_version)`. Frozen once a run cites it.  |
| `model_runs` | One doc per `(scan, prompt, model, doubled, trial)` response, with `scores[]`. |
| `counters`   | Integer `_id` generator. Leave it alone.                                 |

The `model_runs` fields worth knowing:

| Field           | Meaning                                                              |
|-----------------|----------------------------------------------------------------------|
| `scan_id`       | Which scan's payload went in.                                        |
| `prompt_id`     | Which prompt was used (`null` for `nmap` baseline rows).             |
| `doubled`       | `false` = normal system+user; `true` = prompt and payload repeated once. |
| `trial_number`  | 1-based counter per `(scan, prompt, doubled, model.name)`.           |
| `model.name`    | The model, or `nmap` on baseline rows.                               |
| `parsed_output` | `{"cpes": [...]}` pulled from `raw_output`; this is what the scorer reads. |
| `scores`        | Per-prediction scoring rows, written by `score.py`.                  |

## Supported `run.py` backends

`config.toml` `[model].backend` takes:

- `ollama` — local Ollama (`ollama_host`)
- `vllm` — local vLLM's OpenAI-compatible API (`vllm_host`; `/v1` is appended for you)
- `huggingface` — local transformers pipeline (no host)
- `api` — OpenAI API (`api_endpoint`; leave empty for the OpenAI default; reads `OPENAI_API_KEY`)
- `cli` — any local CLI that takes a prompt on stdin (`cli_command`, the full argv vector).
  Sampling args aren't forwarded, so bake them into `cli_command` if the tool takes flags.

## Repository layout

```
config.toml              database URI, model selection, scan-suite definitions
db.py                    shared MongoDB + config helpers, imported everywhere
docker-compose.yml       MongoDB service

run_scans.py             collect nmap scans
ingest.py                parse one XML into devices + scans
truth.py                 load ground truth from Truth.toml
seed_prompts.py          load the 7 prompts (the 2×2 factorial plus 3 extras)
init.py                  create collections + indexes

run.py                   single-scan inference from config.toml (5 backends)
local_run.py             concurrent vLLM sweep
api_run.py               concurrent frontier-API sweep
ollama_cloud_run.py      Ollama Cloud sweep with empty-body retry
baseline.py              synthesize nmap-native baseline runs

score.py                 the scorer
analyze.py               plots, HTML report, analysis context

scripts/                 bootstrap_db.{sh,ps1} and the sweep_* wrappers
archive/                 superseded scripts, kept for provenance only (see below)
```

### About `archive/`

`archive/` holds older versions kept only so the history is legible: `api_run2.py` and
`api_run3.py` (the synchronous runners that came before `api_run.py`), `scores.py` (an
earlier scorer that `score.py` replaced), `export.py` (a generic exporter), `local_run2.py`
(a raw-XML payload experiment that didn't make the results), and the one-off DB inspection
scripts. None of it is on the live path.

One thing to settle before submission. The thesis names `export_thesis_data.py`, along with
the figure generators `make_thesis_png_tables.py` and `plot_tiered_device_heatmap.py`, as
the scripts behind the reported tables and figures. All three are sitting in `archive/`
right now, and the two figure generators import `export_thesis_data` by its old top-level
path, so they won't run from inside `archive/` as-is. Either move them back to the repo root
(simplest, and it matches what the thesis says) or point the thesis text at their new home,
and check the imports resolve whichever way you go.
