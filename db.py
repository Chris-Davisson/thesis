#!/usr/bin/env python3
"""
Shared database and config helpers. Imported by all scripts.

Usage:
    from db import get_connection, load_config, ensure_db
"""

import sqlite3
import sys
import tomllib
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.toml"

REQUIRED_TABLES = [
    "devices",
    "scan_sessions",
    "scan_runs",
    "aggregated_inputs",
    "prompts",
    "experiments",
    "model_runs",
    "ground_truth",
    "scores",
]


def load_config() -> dict:
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def get_connection() -> sqlite3.Connection:
    config = load_config()
    db_path = config["database"]["path"]

    if not db_path:
        print("ERROR: database.path is not set in config.toml")
        sys.exit(1)

    db_path = Path(__file__).parent / db_path
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def ensure_db():
    """Check the DB file exists and all required tables are present. Exit if not."""
    config = load_config()
    db_path = Path(__file__).parent / config["database"]["path"]

    if not db_path.exists():
        print(f"ERROR: Database not found at {db_path}")
        print("       Run init.py first.")
        sys.exit(1)

    con = sqlite3.connect(db_path)
    existing = {
        row[0]
        for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    con.close()

    missing = [t for t in REQUIRED_TABLES if t not in existing]
    if missing:
        print(f"ERROR: Missing tables: {', '.join(missing)}")
        print("       Run init.py first.")
        sys.exit(1)
