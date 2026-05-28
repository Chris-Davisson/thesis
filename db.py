#!/usr/bin/env python3
"""
Shared database and config helpers. Imported by all scripts.

Usage:
    from db import get_db, load_config, ensure_db, next_id
"""

import sys
import tomllib
from pathlib import Path

from pymongo import MongoClient
from pymongo.collection import ReturnDocument

CONFIG_PATH = Path(__file__).parent / "config.toml"

REQUIRED_COLLECTIONS = ["devices", "scans", "prompts", "model_runs", "counters"]

_client: MongoClient | None = None


def load_config() -> dict:
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def get_db():
    """Return the thesis database. Reuses a single MongoClient per process."""
    global _client
    config = load_config()
    uri  = config["database"]["uri"]
    name = config["database"]["name"]

    if not uri or not name:
        print("ERROR: database.uri and database.name must be set in config.toml")
        sys.exit(1)

    if _client is None:
        _client = MongoClient(uri)
    return _client[name]


def next_id(db, collection_name: str) -> int:
    """Atomic counter: return the next integer _id for a named collection."""
    doc = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return doc["seq"]


def ensure_db():
    """Check all required collections exist. Exit with an install hint if not."""
    db = get_db()
    existing = set(db.list_collection_names())
    missing  = [c for c in REQUIRED_COLLECTIONS if c not in existing]
    if missing:
        print(f"ERROR: Missing collections: {', '.join(missing)}")
        print("       Run init.py first.")
        sys.exit(1)
