#!/usr/bin/env python3
"""
Seed the prompts table from the PROMPTS list below.

Idempotent via (prompt_name, prompt_version) — rerunning updates existing rows
with matching name+version, inserts new ones. Use a new prompt_version when
you change an existing prompt's text, so old model_runs still reference the
exact text they ran against.

Usage:
    python seed_prompts.py         # insert/update all prompts
    python seed_prompts.py --list  # show what's currently in the DB
"""

import argparse
import sys

from db import ensure_db, get_connection


# ---------------------------------------------------------------------------
# Prompts to seed. Add new entries here and re-run.
# When revising an existing prompt, bump the version (e.g. "1.0" -> "1.1").
# ---------------------------------------------------------------------------

PROMPTS = [
    {
        "name":    "neutral_minimal",
        "version": "1.0",
        "notes":   "Cell 1 of 2x2: no persona, no structure. Pure task description. Predicted strongest on pure fact retrieval per Hu et al. 2026 (USC PRISM paper).",
        "text":    """Given nmap scan data for a single network device, output CPE 2.3 strings identifying the device.

End your response with a JSON object: {"cpes": ["cpe:2.3:...", ...]}""",
    },
    {
        "name":    "neutral_structured",
        "version": "1.0",
        "notes":   "Cell 2 of 2x2: no persona, structure present. Tests whether format guidance helps independent of persona framing.",
        "text":    """Given nmap scan data for a single network device, output CPE 2.3 strings identifying the device.

Rules:
- Generate CPEs for hardware (h), OS/firmware (o), and applications (a) that can be confidently identified
- Vendor and product are required — omit a CPE entirely if either cannot be identified with confidence
- Use * for version if uncertain; do not guess
- Use * for unknown fields, - for not applicable
- End the response with exactly one JSON object: {"cpes": ["cpe:2.3:...", ...]}

CPE format:
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

Example:
{"cpes": ["cpe:2.3:h:arris:tg1672g:*:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:3.2:*:*:*:*:*:*:*", "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*"]}""",
    },
    {
        "name":    "persona_minimal",
        "version": "1.0",
        "notes":   "Cell 3 of 2x2: persona present, no structure. Tests whether persona framing alone affects output on a fact-retrieval task.",
        "text":    """You are a cybersecurity analyst. Given nmap scan data for a single network device, identify the device and output CPE 2.3 strings.

End your response with a JSON object: {"cpes": ["cpe:2.3:...", ...]}""",
    },
    {
        "name":    "persona_structured",
        "version": "1.0",
        "notes":   "Cell 4 of 2x2: persona + structure. Control for 'typical' expert-prompting practice. Matches the original config.toml prompt.",
        "text":    """You are a cybersecurity analyst. Given nmap scan data for a single network device, identify the device and output CPE 2.3 strings.

Rules:
- Generate CPEs for hardware (h), OS/firmware (o), and applications (a) you can confidently identify
- Vendor and product are required — omit a CPE entirely if you cannot identify both with confidence
- Use * for version if uncertain; do not guess
- Use * for unknown fields, - for not applicable
- End your response with exactly one JSON object: {"cpes": ["cpe:2.3:...", ...]}

CPE format:
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

Example:
{"cpes": ["cpe:2.3:h:arris:tg1672g:*:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:3.2:*:*:*:*:*:*:*", "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*"]}""",
    },
]


# ---------------------------------------------------------------------------

def upsert_prompt(con, name, version, text, notes):
    existing = con.execute(
        "SELECT id FROM prompts WHERE prompt_name = ? AND prompt_version = ?",
        (name, version),
    ).fetchone()

    if existing:
        con.execute(
            "UPDATE prompts SET prompt_text = ?, notes = ? WHERE id = ?",
            (text, notes, existing["id"]),
        )
        print(f"  UPDATE  id={existing['id']}  {name} v{version}")
        return existing["id"]
    else:
        cur = con.execute(
            "INSERT INTO prompts (prompt_name, prompt_version, prompt_text, notes) VALUES (?, ?, ?, ?)",
            (name, version, text, notes),
        )
        print(f"  INSERT  id={cur.lastrowid}  {name} v{version}")
        return cur.lastrowid


def list_prompts(con):
    rows = con.execute(
        "SELECT id, prompt_name, prompt_version, notes FROM prompts ORDER BY id"
    ).fetchall()
    if not rows:
        print("(no prompts in DB)")
        return
    for row in rows:
        print(f"  id={row['id']}  {row['prompt_name']} v{row['prompt_version']}  — {row['notes'] or ''}")


def main():
    parser = argparse.ArgumentParser(description="Seed the prompts table")
    parser.add_argument("--list", action="store_true", help="Show current prompts and exit")
    args = parser.parse_args()

    ensure_db()
    con = get_connection()

    if args.list:
        list_prompts(con)
        con.close()
        return

    for p in PROMPTS:
        upsert_prompt(con, p["name"], p["version"], p["text"], p["notes"])

    con.commit()
    con.close()
    print("\nDone. Use `python seed_prompts.py --list` to see all prompts and their IDs.")


if __name__ == "__main__":
    main()