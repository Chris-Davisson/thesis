# Tech Doc — LLM-Assisted CPE Identification Thesis

The design rationale for the thesis tool. For "how to run it," see `README.md`.
This document is for future-me reconstructing why things are shaped the way
they are.

## Purpose

Test whether LLMs can produce more accurate CPE 2.3 identifications than nmap
alone when given the same scan data, across different model sizes and
deployment modes. The privacy axis matters: if a small local model performs
nearly as well as a cloud API, that's a viable privacy-preserving tool for
enterprise IoT security where scan data can't leave the network.

The research question reduces to one empirical claim: *given only nmap output,
is LLM-generated CPE accuracy high enough to enable CVE lookup that the nmap
baseline misses?*

## Architecture — Database-First, CLI-Only

Every piece of state lives in a single SQLite file. Every script calls
`ensure_db()` at startup to verify the file and tables exist. Scripts don't
talk to each other; they share the DB. There is no web server, REST API,
frontend, or service manager — by choice, after an earlier web-UI iteration
created a cascade of "is it the API, the endpoint, the device, the pipeline,
or the DB" debugging. CLI scripts with clear scope keep failure modes
isolated.

## Pipeline Flow

```
run_scans.py   → writes nmap XML files to scans/<ip>_<ts>/
     ↓
ingest.py      → parses XML → devices + scan_sessions + scan_runs + aggregated_inputs
     ↓
truth.py       → reads [[truth]] blocks from config.toml → ground_truth
     ↓
baseline.py    → extracts nmap's own CPEs from scan XML → synthetic model_runs row (model_name='nmap')
     ↓
run.py         → LLM call using prompt from DB + scan payload → model_runs row
     ↓
scores.py      → compares predicted CPEs vs ground_truth → one scores row per predicted CPE
     ↓
export.py      → (not yet written) dumps flat CSV for external analysis
```

Each script is independent. Re-running any one does not re-run the others.
`scan_runs` are ingested once and reused; the LLM can be called many times
against the same `aggregated_input_id` with different models/prompts.

## Experimental Design — Option Y (factors, not conditions)

There is no `experiments` table wiring. Each `model_run` records its full
configuration directly:

- `aggregated_input_id` — which scan, on which device
- `prompt_id` — which prompt text was used (from the `prompts` table)
- `model_name`, `model_version` — which LLM
- `temperature`, `top_p`, `seed`, `max_tokens` — which settings

This is a factorial design. Every run is a point in configuration space;
the space is sliced at analysis time with SQL WHERE clauses. The
`experiments` table exists in the schema for historical reasons but is
never populated. `experiment_id` in `model_runs` is always NULL.

Rejected alternative: pre-registered "experimental conditions" (A, B, C, D
as bundled configs). Rejected because it bundles factors that should stay
independent — every cross-cutting question ("how does prompt length affect
accuracy, averaged across models?") would require decomposing condition
labels back into factors.

## Key Tables

- **devices** — physical lab device registry. Keyed by unique `device_code`
  (e.g. `linksys-wrt54gs`). Stores `mac`, `manufacturer`, `model`,
  `firmware_version`, `device_type`. Populated partially by `ingest.py` (mac,
  manufacturer from nmap OUI lookup) and partially left for manual editing.

- **scan_sessions** — one row per scan event for a device. Records
  `target_ip`, `hostname`, `started_at`, `ended_at`, `operator`,
  `network_name`.

- **scan_runs** — one row per individual nmap execution within a session.
  Stores `command`, `stdout_text` (raw XML), `exit_code`, `tool_name`,
  `tool_version`, `parsed_data_json`. The raw XML is kept so any parser can
  be re-run later without re-scanning.

- **aggregated_inputs** — consolidated LLM-ready payload built from one
  scan_run. `variant_name` and `parser_version` track how the payload was
  constructed. `input_payload_json` currently stores plain text despite the
  column name — readable for humans, token-efficient for LLMs. This is what
  the LLM sees.

- **prompts** — one row per prompt, identified by `(prompt_name,
  prompt_version)`. Prompts live in the DB so every `model_run` can point to
  the exact text it used, even if that prompt is later revised. Seeded by
  `seed_prompts.py`. When revising, bump `prompt_version` to preserve the
  old row.

- **experiments** — exists in schema, unused. See "Option Y" above.

- **model_runs** — one row per LLM call (and per nmap baseline synthesis).
  Stamped with `aggregated_input_id`, `prompt_id`, `model_name`,
  `model_version`, `temperature`, `top_p`, `max_tokens`, `seed`,
  `trial_number`. Stores `raw_output_text`, `parsed_output_json`,
  `conversation_history_json`, `status`, `error_text`. Baseline rows
  (`model_name='nmap'`) have NULL for prompt_id, temperature, etc., and
  synthetic JSON for `parsed_output_json`.

- **ground_truth** — manually labeled true vendor/product/firmware/CPEs per
  device. `accepted_cpes_json` uses tiered format:
  `[{cpe = "...", tier = "exact"|"partial"|"related"}]`. One row per device,
  upserted by `truth.py`.

- **scores** — one row per (model_run, predicted_cpe) pair. For each
  prediction, the scorer finds the best-matching accepted CPE (highest tier,
  tiebroken by field-match count) and records field-level booleans:
  `part_correct`, `vendor_correct`, `product_correct`, `version_correct`,
  `exact_match`, `cve_lookup_valid`. Also records `best_match_tier` and
  `match_score` (numeric 1.0 / 0.5 / 0.25 / 0.0).

## Scoring Rubric

The match hierarchy for "how useful is this prediction for CVE lookup":

1. **Exact** — `part:vendor:product:version` all correct. Full CVE lookup works.
2. **CVE-lookup valid** — `part:vendor:product` correct, version wildcard or
   wrong. Finds CVEs for the product; some won't apply.
3. **Partial** — correct but lossy. "linux_kernel" for a Fire TV running Fire
   OS: technically right, misses Amazon-specific CVEs. Tier is assigned in
   ground truth.
4. **Related** — same family/category, wrong product. Assigned in ground truth.
5. **None** — no match.

Multi-CPE scoring: each predicted CPE is scored independently against the
whole accepted set. One `scores` row per prediction. Aggregation happens at
analysis time.

## The nmap Baseline

nmap is treated as a synthetic "model" — `baseline.py` extracts the CPEs
nmap itself emitted (from `<service><cpe>` and `<osclass cpe="...">`),
normalizes short-form to CPE 2.3 long form, and writes a `model_runs` row
with `model_name='nmap'`. The scorer treats this row identically to an LLM
run. All analysis queries filter by `model_name` to separate baseline from
LLM results.

Rejected alternative: a `nmap_baseline_cpes_json` column on each LLM
model_run row. Rejected because it breaks the `scores` table's clean "one
row per predicted CPE" structure — a single model_run would carry two
prediction sets, requiring a discriminator column and forever-complicating
every analysis query.

## Scan Suite

Six scans per device, each stressing a different detection mechanism:

| # | Flags | What it captures |
|---|---|---|
| 01 | `-sV --version-intensity 5 -O -sC --top-ports 1000 -T4` | Full service + OS detection, default scripts |
| 02 | `-sV --version-intensity 1` | Version detection, low probe depth |
| 03 | `-sV --version-intensity 5` | Version detection, medium probe depth |
| 04 | `-sV --version-intensity 9` | Version detection, max probe depth |
| 05 | `--script dns-service-discovery -sU -p 5353` | mDNS/Bonjour (reveals device name/type) |
| 06 | `--script upnp-info -sU -p 1900` | UPnP (manufacturer/model strings) |

Each scan XML is ingested independently so simpler scans can be tested
against the full suite — useful for the secondary question "does a cheaper
scan yield comparable LLM accuracy?"

## CPE Format

```
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
```

| Field | Description | Example |
|---|---|---|
| part | `h` hardware, `o` OS, `a` application | `h` |
| vendor | Lowercase, underscores for spaces | `linksys` |
| product | Lowercase product name | `wrt54gs` |
| version | Specific version | `2.0` |
| update..other | Usually `*` in practice | `*` |

`*` = any value. `-` = not applicable. For thesis purposes, only
**part:vendor:product:version** matter — everything else is `*` in almost
every real case.

The LLM is instructed to omit a CPE entirely rather than guess the version.
The CPE validator in `run.py` rejects CPEs with wildcard vendor or product,
since those are useless for CVE lookup.

## Research Basis

| Paper | Contribution to this system |
|---|---|
| Sivanathan et al. — IoT Traffic Classification | Establishes port numbers, service banners, hostnames, and cipher suites as the discriminating features for IoT identification. Grounds the choice of nmap as the data source. |
| Hu & Thing — CPE-Identifier | Defines the CPE entity types the LLM must output. Finds `product` is the hardest field to classify (87% F1 vs 95%+ for others) — informs the field-level scoring design. |
| Sanguino & Uetz — CPE/CVE Structural Analysis | Documents NVD data quality problems (~895 CVEs with no CPE entries, ~105k CPE entries referencing nonexistent dictionary entries). Justifies removing the CVE stage — CPE accuracy is the meaningful measure. Establishes vendor + product + version as highest-weight WFN attributes. |
| AutoPenBench | Justifies temperature=0 and fixed seed for reproducibility. Justifies `trial_number` in model_runs — LLM outputs vary across identical-input runs. |
| xOffense | Justifies the aggregated_inputs design — structured grey-box input outperforms raw command output. Supports testing small fine-tuned local models against large commercial APIs. |
| PentestGPT | Justifies storing `conversation_history_json` in model_runs — full history logging is necessary for reproducibility and context management. |
| IoT Sentinel | Prior work context for IoT device identification. Background rather than direct basis. |

## Out of Scope (by choice)

- Web server, REST API, frontend
- Live scan execution (handled by `run_scans.py` as a separate script)
- Statistical calculations (done externally on exported data)
- CVE lookup evaluation — CVEs are downstream of CPEs; CPE errors propagate
  directly, so CVE scoring adds no independent signal
- Hallucination detection (future work — see below)
- Network traffic analysis / pcap — changes the research question; out of
  scope for this thesis

## Future Work

### Hallucination detection

The scorer does not verify that predicted vendor:product pairs exist in the
official NIST CPE dictionary. A fabricated but structurally-valid CPE (the
LLM inventing "smart_devices_inc" as a vendor) scores as 0 via the no-match
path but is not distinguished from a legitimate wrong guess.

To add:
1. Download the NVD CPE dictionary (https://nvd.nist.gov/products/cpe),
   ~1.5M entries, refreshed daily.
2. Index by (vendor, product) tuples.
3. Add a `hallucinated INTEGER` column to `scores`.
4. In `score_prediction()`, mark predictions whose (vendor, product) pair is
   not in the dictionary.

This separates "wrong but plausible" from "fabricated" — an important
failure-mode signal.

### Input-format comparison

Currently the LLM sees plain-text aggregated input. Open question: does
the model do better on raw XML? Structured JSON? Truncated plain text? The
`variant_name` field on `aggregated_inputs` exists for this — multiple
variants could be built from the same scan_run and compared.

### Export / analysis pipeline

`export.py` is empty. Minimum viable version: dump a wide CSV joining
`scores`, `model_runs`, `devices`, `ground_truth`, `prompts`. One row per
predicted CPE. Feed into pandas/R/Excel for figures.