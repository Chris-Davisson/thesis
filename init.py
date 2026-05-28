#!/usr/bin/env python3
"""
Initialise the MongoDB database: create collections, indexes, counters.
Safe to run multiple times — idempotent.

Usage:
    python init.py
"""

from pymongo.errors import CollectionInvalid

from db import get_db


COLLECTIONS = ["devices", "scans", "prompts", "model_runs", "counters"]

INDEXES = {
    "devices": [
        ([("device_code", 1)], {"unique": True, "name": "device_code_unique"}),
        ([("mac", 1)],         {"unique": True, "sparse": True, "name": "mac_unique_sparse"}),
    ],
    "scans": [
        ([("device_id", 1)], {"name": "device_id"}),
    ],
    "prompts": [
        ([("prompt_name", 1), ("prompt_version", 1)],
         {"unique": True, "name": "name_version_unique"}),
    ],
    "model_runs": [
        ([("scan_id", 1)],                        {"name": "scan_id"}),
        ([("prompt_id", 1)],                      {"name": "prompt_id"}),
        ([("scan_id", 1), ("model.name", 1)],     {"name": "scan_id_model_name"}),
    ],
}


def main():
    db = get_db()

    for name in COLLECTIONS:
        try:
            db.create_collection(name)
            print(f"  CREATE  {name}")
        except CollectionInvalid:
            print(f"  exists  {name}")

    for coll_name, idx_specs in INDEXES.items():
        for keys, opts in idx_specs:
            db[coll_name].create_index(keys, **opts)
            print(f"  INDEX   {coll_name}.{opts['name']}")

    print("\nDatabase ready.")


if __name__ == "__main__":
    main()
