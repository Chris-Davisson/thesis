# Thesis — LLM-Assisted CPE Identification

Future-me reading this in two months: you built a pipeline that feeds nmap
scan data to an LLM, asks it to produce CPE 2.3 strings, and scores them
against manually-labeled ground truth. The design rationale is in
`Documents/Tech_Doc.md`. This file is the muscle memory.

## One-time setup

```bash
# From the Thesis/ directory
python -m venv .venv
source .venv/bin/activate                # or .venv\Scripts\activate on Windows
pip install python-dotenv ollama openai anthropic

# Create the DB
python init.py

# Seed the prompts
python seed_prompts.py
python seed_prompts.py --list            # note the prompt IDs
```

If you need API keys, put them in `.env` (gitignored):
```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

## The workflow for one device

```bash
# 1. Run the scan suite (needs root for -O and UDP scans)
sudo python run_scans.py 192.168.1.1
#    → writes XMLs to scans/192.168.1.1_<timestamp>/

# 2. Ingest each scan XML
python ingest.py scans/192.168.1.1_<ts>/01-sv-osc-top1000.xml linksys-wrt54gs
#    → prints device_id and aggregated_input_id — write these down

# 3. Add ground truth for the device
#    Edit config.toml: uncomment/add a [[truth]] block with the real
#    vendor/product/firmware/CPEs. Then:
python truth.py
#    → upserts ground_truth rows for every [[truth]] block in config

# 4. Build the nmap baseline
python baseline.py <aggregated_input_id>
#    → creates a model_run with model_name='nmap'

# 5. Run the LLM
#    Edit config.toml: set [model] and [prompt].prompt_id to what you want
python run.py <aggregated_input_id>
#    → creates a model_run with the LLM's output

# 6. Score everything
python scores.py --all
#    → writes scores rows for every unscored model_run (LLM + baseline)
```

## The sweep workflow — many models × prompts on one scan

```bash
# For each prompt_id:
#   For each model config:
#     edit config.toml, python run.py <agg_id>
#
# Then:
python scores.py --all
```

A shell loop is fine. There's no batch runner because I'd rather edit
config.toml than debug a batch script that gets the combinations wrong.

## Scripts

| Script | What it does |
|---|---|
| `init.py` | Creates the SQLite DB and all tables. Idempotent. Run once. |
| `seed_prompts.py` | Inserts prompts from the `PROMPTS` list into the DB. `--list` shows what's there. Re-run after editing the list. |
| `run_scans.py <ip>` | Runs the six-scan nmap suite against an IP. Writes XMLs to `scans/`. |
| `ingest.py <xml> <device_code>` | Parses one nmap XML, creates a device (if new), scan_session, scan_run, and aggregated_input. Prints the aggregated_input_id. |
| `truth.py` | Reads `[[truth]]` blocks from config.toml, upserts ground_truth rows by MAC address. |
| `baseline.py <agg_id>` | Extracts nmap's own CPEs from the scan XML and writes them as a synthetic model_run with `model_name='nmap'`. `--all` or `--rebuild <id>` also work. |
| `run.py <agg_id>` | Reads model/prompt config from config.toml, calls the LLM, writes one model_runs row. |
| `scores.py <run_id>` | Compares predicted CPEs against ground_truth, writes per-prediction scores rows. `--all` or `--rescore <id>` also work. |
| `export.py` | Empty. TODO: dump a flat CSV for pandas/R/Excel. |
| `db.py` | Shared helpers — `load_config()`, `get_connection()`, `ensure_db()`. Imported by everything. |

## config.toml — the one file you'll edit during experiments

```toml
[database]
path = "thesis.db"

[model]
backend = "ollama"                       # ollama | huggingface | api
name = "deepseek-r1:1.5b"
version = ""
Host_IP = "http://localhost:11434"       # Ollama — leave empty to use vLLM
VLLM_Host = "http://10.101.68.83:8001"   # vLLM — /v1 is appended automatically
endpoint = ""                            # API backend only
max_tokens = 2048
temperature = 0.0
top_p = 1.0
seed = 42

[prompt]
prompt_id = 2                            # from `python seed_prompts.py --list`

[[scans]]
# ... six scan definitions ...

[[truth]]
# One block per device. mac is used to resolve device_id. accepted_cpes
# uses tiered format — tier is "exact", "partial", or "related".
ip = "192.168.1.1"
mac = "AA:BB:CC:DD:EE:FF"
true_vendor = "amazon"
true_product = "fire_tv"
true_firmware_version = "7.2.3.3"
accepted_cpes = [
    {cpe = "cpe:2.3:h:amazon:fire_tv:*:*:*:*:*:*:*:*", tier = "exact"},
    {cpe = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", tier = "partial"},
]
rubric_version = "1.0"
label_status = "verified"
notes = ""
```

**Which fields change between runs?** Just these:

- `[model].backend`, `[model].name`, `[model].temperature`, `[model].seed` — to test different models/settings
- `[prompt].prompt_id` — to test different prompts
- `[[scans]]` — rarely, only if you're revising the scan suite
- `[[truth]]` — once per new device

Everything else stays put.

## Backend gotchas

- **Ollama vs vLLM:** If both `Host_IP` and `VLLM_Host` are set, Ollama wins.
  To test vLLM, clear `Host_IP` (empty string).
- **vLLM endpoint:** `VLLM_Host` should be the base URL. `/v1` is appended
  in code — don't include it in config.
- **Anthropic seed:** Claude API doesn't support seed. `run.py` writes NULL
  for seed on Anthropic runs automatically.
- **First time using a local model:** `ollama pull deepseek-r1:1.5b` before
  running. `run.py` will error with a clear message if the model isn't pulled.

## Useful analysis queries

Once you have data:

```sql
-- Head-to-head by model, per device
SELECT d.device_code, mr.model_name,
       COUNT(s.id) AS n_predictions,
       ROUND(AVG(s.match_score), 3) AS avg_match,
       SUM(s.exact_match) AS exact,
       SUM(s.cve_lookup_valid) AS cve_valid
FROM scores s
JOIN model_runs mr ON mr.id = s.model_run_id
JOIN aggregated_inputs ai ON ai.id = mr.aggregated_input_id
JOIN scan_sessions ss ON ss.id = ai.scan_session_id
JOIN devices d ON d.id = ss.device_id
GROUP BY d.device_code, mr.model_name
ORDER BY d.device_code, avg_match DESC;

-- Prompt effect, averaged across everything
SELECT p.prompt_name, p.prompt_version,
       ROUND(AVG(s.match_score), 3) AS avg_match,
       COUNT(DISTINCT mr.id) AS n_runs
FROM scores s
JOIN model_runs mr ON mr.id = s.model_run_id
JOIN prompts p ON p.id = mr.prompt_id
GROUP BY p.prompt_name, p.prompt_version
ORDER BY avg_match DESC;

-- Variance for repeated runs (same input, same model, same prompt)
SELECT mr.aggregated_input_id, mr.model_name, mr.prompt_id,
       COUNT(DISTINCT mr.id) AS trials,
       ROUND(AVG(s.match_score), 3) AS avg_match,
       ROUND(MIN(s.match_score), 3) AS min_match,
       ROUND(MAX(s.match_score), 3) AS max_match
FROM scores s
JOIN model_runs mr ON mr.id = s.model_run_id
GROUP BY mr.aggregated_input_id, mr.model_name, mr.prompt_id
HAVING trials > 1;
```

## Things I know I'll forget

- **Ingest order matters for truth.py.** `truth.py` resolves devices by MAC,
  which comes from `ingest.py`. Ingest first, truth second.
- **`baseline.py` can run before any LLM runs.** It doesn't depend on
  `run.py`. Good idea to run it right after ingest so every aggregated_input
  has a baseline before you start sweeping.
- **Re-seeding prompts with a new version creates a new row.** If I just fix
  a typo and keep the version, `seed_prompts.py` updates in place. If I
  change the actual prompt behavior, I bump the version — old model_runs
  keep pointing to the old text.
- **Scoring is idempotent per model_run.** `scores.py <id>` skips already-scored
  runs. Use `--rescore <id>` to force redo after changing ground truth.
- **`ingest.py` doesn't extract OS-level CPEs from `<osclass>`.** Only
  service-level CPEs end up in `parsed_data_json`. `baseline.py` re-parses
  the raw XML to get both. Don't rely on `parsed_data_json` for a complete
  CPE list.
- **Dropping the DB is cheap.** Until there's real data, `rm thesis.db && python init.py && python seed_prompts.py`
  is faster than any migration.