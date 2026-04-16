#!/usr/bin/env python3
"""
Initialise the SQLite database and create all tables.
Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS.

Usage:
    python init.py
"""

import sqlite3
import sys
import tomllib
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.toml"


def load_config():
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


SCHEMA = [
    (
        "devices",
        """
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_code TEXT NOT NULL UNIQUE,
            mac         TEXT UNIQUE,
            display_name TEXT,
            manufacturer TEXT,
            model       TEXT,
            firmware_version TEXT,
            device_type TEXT,
            notes       TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        )
        """,
        [],
    ),
    (
        "scan_sessions",
        """
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id        INTEGER NOT NULL REFERENCES devices(id),
            target_ip        TEXT,
            hostname         TEXT,
            started_at       TEXT DEFAULT (datetime('now')),
            ended_at         TEXT,
            network_name     TEXT,
            environment_notes TEXT,
            operator         TEXT,
            protocol_version TEXT
        )
        """,
        [
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_device_id ON scan_sessions(device_id)",
        ],
    ),
    (
        "scan_runs",
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_session_id INTEGER NOT NULL REFERENCES scan_sessions(id),
            scan_name       TEXT,
            command         TEXT,
            stdout_text     TEXT,
            stderr_text     TEXT,
            exit_code       INTEGER,
            started_at      TEXT DEFAULT (datetime('now')),
            ended_at        TEXT,
            tool_name       TEXT,
            tool_version    TEXT,
            parsed_data_json TEXT
        )
        """,
        [
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_session_id ON scan_runs(scan_session_id)",
        ],
    ),
    (
        "aggregated_inputs",
        """
        CREATE TABLE IF NOT EXISTS aggregated_inputs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_session_id  INTEGER NOT NULL REFERENCES scan_sessions(id),
            variant_name     TEXT,
            parser_version   TEXT,
            input_payload_json TEXT,
            created_at       TEXT DEFAULT (datetime('now')),
            notes            TEXT
        )
        """,
        [
            "CREATE INDEX IF NOT EXISTS idx_aggregated_inputs_session_id ON aggregated_inputs(scan_session_id)",
        ],
    ),
    (
        "prompts",
        """
        CREATE TABLE IF NOT EXISTS prompts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_name    TEXT,
            prompt_version TEXT,
            prompt_text    TEXT NOT NULL,
            created_at     TEXT DEFAULT (datetime('now')),
            notes          TEXT
        )
        """,
        [],
    ),
    (
        "experiments",
        """
        CREATE TABLE IF NOT EXISTS experiments (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            model_name    TEXT,
            model_version TEXT,
            prompt_id     INTEGER REFERENCES prompts(id),
            temperature   REAL,
            top_p         REAL,
            seed          INTEGER,
            notes         TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        )
        """,
        [],
    ),
    (
        "model_runs",
        """
        CREATE TABLE IF NOT EXISTS model_runs (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            aggregated_input_id     INTEGER NOT NULL REFERENCES aggregated_inputs(id),
            experiment_id           INTEGER REFERENCES experiments(id),
            prompt_id               INTEGER REFERENCES prompts(id),
            trial_number            INTEGER,
            model_name              TEXT,
            model_version           TEXT,
            temperature             REAL,
            top_p                   REAL,
            max_tokens              INTEGER,
            seed                    INTEGER,
            conversation_history_json TEXT,
            raw_output_text         TEXT,
            parsed_output_json      TEXT,
            started_at              TEXT DEFAULT (datetime('now')),
            ended_at                TEXT,
            status                  TEXT DEFAULT 'pending',
            error_text              TEXT
        )
        """,
        [
            "CREATE INDEX IF NOT EXISTS idx_model_runs_aggregated_input_id ON model_runs(aggregated_input_id)",
            "CREATE INDEX IF NOT EXISTS idx_model_runs_experiment_id ON model_runs(experiment_id)",
        ],
    ),
    (
        "ground_truth",
        """
        CREATE TABLE IF NOT EXISTS ground_truth (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id            INTEGER NOT NULL REFERENCES devices(id),
            true_vendor          TEXT,
            true_product         TEXT,
            true_firmware_version TEXT,
            accepted_cpes_json   TEXT,
            rubric_version       TEXT,
            label_status         TEXT,
            notes                TEXT,
            created_at           TEXT DEFAULT (datetime('now')),
            updated_at           TEXT DEFAULT (datetime('now'))
        )
        """,
        [],
    ),
(
        "scores",
        """
        CREATE TABLE IF NOT EXISTS scores (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            model_run_id         INTEGER NOT NULL REFERENCES model_runs(id),
            ground_truth_id      INTEGER NOT NULL REFERENCES ground_truth(id),
            predicted_cpe        TEXT,
            matched_accepted_cpe TEXT,
            part_correct         INTEGER,
            vendor_correct       INTEGER,
            product_correct      INTEGER,
            version_correct      INTEGER,
            exact_match          INTEGER,
            cve_lookup_valid     INTEGER,
            best_match_tier      TEXT,
            match_score          REAL,
            predicted_vendor     TEXT,
            predicted_product    TEXT,
            score_notes          TEXT,
            scorer_version       TEXT,
            created_at           TEXT DEFAULT (datetime('now'))
        )
        """,
        [
            "CREATE INDEX IF NOT EXISTS idx_scores_model_run_id ON scores(model_run_id)",
        ],
    ),
]


def main():
    config = load_config()
    db_path = config["database"]["path"]

    if not db_path:
        print("ERROR: database.path is not set in config.toml")
        sys.exit(1)

    db_path = Path(__file__).parent / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON")

    for table_name, create_sql, indexes in SCHEMA:
        con.execute(create_sql)
        for idx_sql in indexes:
            con.execute(idx_sql)
        print(f"  OK  {table_name}")

    con.commit()
    con.close()

    print(f"\nDatabase ready: {db_path}")


if __name__ == "__main__":
    main()
