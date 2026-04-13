● System Design — AI Pentesting Thesis Tool

  Purpose

  A set of independent Python programs that share a single SQLite database. Each program does one job. They are run
  manually in sequence as needed. The goal is to test whether LLMs can produce more accurate CPE identifications than
  nmap on IoT device scan data, across different model sizes and backends, to evaluate whether a small local model is
  viable as a privacy-preserving alternative to cloud API calls.

  ---
  Configuration

  Two config files:

  - .env — API keys (never committed)
  - config.toml — model backend, model name, model version, endpoint URL, database path

  Supported backends: Ollama, HuggingFace local, API (e.g. Claude, OpenAI).

  ---
  Database

  SQLite file at a path defined in config.toml. Schema is created by init.py on first run. All other programs call a
  shared ensure_db() at startup that verifies the file and tables exist. The authoritative schema is
  drawSQL-mysql-export-2026-04-12.sql (MySQL syntax; translated to SQLite in init.py).

  Tables:

  - devices — one row per physical lab device. Identified by a short unique device_code (e.g. linksys-wrt54gs).
    Also stores mac, display_name, manufacturer, model, firmware_version, device_type.
  - scan_sessions — one row per scan event for a device. Records target_ip, hostname, timestamps, operator,
    network_name.
  - scan_runs — one row per individual nmap execution within a session. Stores command, stdout_text (raw XML),
    stderr_text, exit_code, tool_name, tool_version, parsed_data_json.
  - aggregated_inputs — one row per consolidated input payload built from a session's scan runs. Has variant_name
    and parser_version to track how the payload was constructed. This is what gets fed to the LLM.
  - prompts — one row per prompt version. Stores prompt_name, prompt_version, prompt_text. Prompts are stored in
    the DB, not as files. Must be inserted before setup.py is run.
  - experiments — one row per experimental condition. References a prompt_id and defines model_name, model_version,
    temperature, top_p, seed, max_tokens. Created once, referenced by many runs. seed is stored as NULL for
    backends that do not support it (e.g. Claude API).
  - model_runs — one row per LLM call. References aggregated_input_id, experiment_id, prompt_id, trial_number.
    Stores model parameters (duplicated from experiment for immutable record), conversation_history_json,
    raw_output_text, parsed_output_json, status, error_text, and timestamps.
  - ground_truth — one row per device. Stores true_vendor, true_product, true_firmware_version, accepted_cpes_json,
    rubric_version, label_status. Manually entered.
  - scores — one row per evaluated model_run. References model_run_id and ground_truth_id. Stores predicted_vendor,
    predicted_product, predicted_cpes_json, exact_match, partial_credit_level, score_type, scorer_version.

  ---
  Programs

  init.py
  Creates the database file, all tables, and indexes. Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS.
  Prints confirmation that the schema is ready.
  Writes: all tables (schema only).

  ingest.py
  Accepts a path to an nmap XML file and a device code. Parses the XML, creates a device row if one does not already
  exist for that code, creates a scan_session row, creates scan_run rows for each scan in the file, and builds an
  aggregated_input row from the parsed data. Prints the resulting device_id and aggregated_input_id.
  Reads: devices.
  Writes: devices (if new), scan_sessions, scan_runs, aggregated_inputs.

  truth.py
  Accepts a device code and ground truth values (vendor, product, firmware version, CPE list, label status, notes).
  Upserts a single ground_truth row for that device.
  Reads: devices (resolve device_code to id).
  Writes: ground_truth.

  setup.py
  Accepts experiment parameters (name, model name, model version, temperature, top_p, seed, max_tokens, prompt_id,
  notes) and creates an experiment row. Prints the experiment_id.
  Reads: prompts (validate prompt_id exists).
  Writes: experiments.

  run.py
  Accepts a device_id, an experiment_id, and a trial number. Fetches the prompt from the DB via the experiment's
  prompt_id, builds the input from the aggregated_input record, calls the LLM once, and writes a single model_run
  row. The prompt instructs the model to reason about the device first and then output a JSON array of CPE 2.3
  strings. conversation_history_json stores the full message array sent to the API for reproducibility.
  Reads: experiments, prompts, aggregated_inputs.
  Writes: model_runs.

  export.py
  Accepts an experiment_id and optionally a device_id. For each relevant model_run, compares parsed_output_json
  against ground_truth, writes scores rows, and dumps a CSV or JSON file containing all model_runs with their
  scores and ground truth side by side. This file is the input to external statistical analysis.
  Reads: model_runs, experiments, aggregated_inputs, ground_truth, devices.
  Writes: scores, CSV/JSON output file.

  ---
  Research Basis — What Each Paper Contributes

  | Paper | What it contributes to this system |
  |---|---|
  | Sivanathan et al. — IoT Traffic Classification | Establishes that port numbers, service banners, hostnames, and cipher suites are the discriminating features for IoT device identification — exactly what nmap captures. Grounds the choice of nmap as the data source. |
  | Hu & Thing — CPE-Identifier | Defines the five CPE entity types the LLM must output: vendor, product, version, update, edition. Finds that product is the hardest to classify (87% F1 vs 95%+ for others) — informs partial credit weighting in scores. |
  | Sanguino & Uetz — CPE/CVE Structural Analysis | Documents NVD data quality problems: ~895 CVEs with no CPE entries, ~105k CPE entries in CVE feeds that don't exist in the CPE dictionary. Justifies removing the CVE stage — CPE accuracy is the meaningful measure; CVE lookup reliability is an NVD data problem, not a model problem. Also establishes that vendor + product + version are the highest-weight WFN attributes for scoring. |
  | AutoPenBench | Justifies temperature=0 and fixed seed in experiments for reproducibility. Justifies trial_number in model_runs — LLM outputs are variable across runs even with identical inputs. Provides model comparison background (GPT-4o, o1, Gemini) as prior work context. |
  | xOffense | Justifies the aggregated_inputs design — structured grey-box input (parsed and consolidated scan data) outperforms raw command output. Supports testing smaller fine-tuned local models against large commercial APIs as a meaningful experiment axis. |
  | PentestGPT | Justifies storing conversation_history_json in model_runs — session summarization and full history logging are necessary for reproducibility and context management in LLM pipelines. |
  | IOT Sentinel | Prior work context for IoT device identification. Less directly applicable than Sivanathan et al. but relevant background for the fingerprinting stage. |

  ---
  What is not included

  - No web server
  - No REST API
  - No frontend
  - No live scan execution (handled externally by run_scans.py or similar)
  - No statistical calculations (done externally on the exported data)
  - No CVE stage — CVEs are downstream of CPEs; any CPE error propagates directly, so CVE evaluation adds no
    independent signal



## Scan Suite

The six scans run against each device, in order:

```bash
nmap -sV --version-intensity 5 -O -sC --top-ports 1000 -T4 -oX 01-sv-osc-top1000.xml <ip>
nmap -sV --version-intensity 1 -oX 02-sv-intensity1.xml <ip>
nmap -sV --version-intensity 5 -oX 03-sv-intensity5.xml <ip>
nmap -sV --version-intensity 9 -oX 04-sv-intensity9.xml <ip>
nmap --script dns-service-discovery -sU -p 5353 -oX 05-dns-sd-udp5353.xml <ip>
nmap --script upnp-info -sU -p 1900 -oX 06-upnp-udp1900.xml <ip>
```

Run via `python run_scans.py <ip>`. Requires root/admin for `-O` and UDP scans.

---

## CPE Format

A CPE (Common Platform Enumeration) string uniquely identifies a piece of hardware or software. The format is CPE 2.3:

```
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
```

| Field | Description | Example |
|---|---|---|
| `part` | `h` = hardware, `o` = OS, `a` = application | `h` |
| `vendor` | Manufacturer name, lowercase, underscores for spaces | `linksys` |
| `product` | Product name, lowercase | `wrt54gs` |
| `version` | Specific version number | `2.0` |
| `update` | Patch or update identifier | `sp1` or `*` |
| `edition` | Edition information | `*` |
| `language` | Language tag | `*` |
| `sw_edition` | Software edition | `*` |
| `target_sw` | Target software environment | `*` |
| `target_hw` | Target hardware architecture | `*` |
| `other` | Any other relevant info | `*` |

`*` means any value. `-` means not applicable.

Example for a Linksys WRT54GS router:
```
cpe:2.3:h:linksys:wrt54gs:2.0:*:*:*:*:*:*:*
```

The three most important fields for matching against CVEs are **vendor**, **product**, and **version**. The LLM is instructed to omit a CPE entirely rather than guess the version.




Continuing work:
 include a compairison of parsed vs unparsed. JSON, XML, plain text ect...