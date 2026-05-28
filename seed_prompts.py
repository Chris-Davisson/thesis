#!/usr/bin/env python3
"""
Seed the prompts collection from the PROMPTS list below.

Idempotent via (prompt_name, prompt_version) — rerunning updates existing docs
with matching name+version, inserts new ones. Use a new prompt_version when
you change an existing prompt's text, so old model_runs still reference the
exact text they ran against.

Usage:
    python seed_prompts.py         # insert/update all prompts
    python seed_prompts.py --list  # show what's currently in the DB
"""

import argparse
from datetime import datetime, timezone

from db import ensure_db, get_db, next_id


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
    {
        "name":    "evidence_first",
        "version": "1.0",
        "notes":   "Chain-of-thought prompt requiring evidence extraction before CPE generation. Tests whether showing work reduces hallucination.",
        "text":    """You are a cybersecurity analyst specializing in device identification. Analyze the provided nmap scan data and follow these steps:

Step 1: Extract specific technical identifiers (banners, HTTP headers, MAC vendor, SMB signatures, script outputs).
Step 2: Based on Step 1, identify the Hardware Vendor, Product Name, and OS.
Step 3: Map these to the CPE 2.3 schema. If you are unsure of a field, use '*'. If a device is a generic Linux box but you can't identify the hardware, omit the 'h' part and focus on 'o'.

Rules:
- ABSTAIN if the evidence is insufficient (e.g., only one open port with no banner).
- DO NOT invent product names.
- FORMAT: Output your reasoning first, followed by a JSON block.

JSON SCHEMA:
{
  "reasoning": "...",
  "cpes": ["cpe:2.3:h:vendor:product:version...", ...]
}""",
    },
    {
        "name":    "few_shot_grounded",
        "version": "1.0",
        "notes":   "Few-shot prompt with positive and negative examples. Tests whether examples improve abstention on weak evidence.",
        "text":    """You are a cybersecurity analyst. Given nmap scan data for a single network device, identify the device and output CPE 2.3 strings.

ABSTENTION RULES (do NOT output a CPE if):
- Banner is generic ("http", "ssl") with no product/version
- OS detection confidence < 50%
- You're guessing vendor or product without evidence
- Only MAC/OUI is available without corroborating hostname, UPnP, or TLS cert

EXAMPLE 1 (strong evidence → output CPEs):
Input: Port 80/tcp: lighttpd 1.4.35 banner, Port 22/tcp: OpenSSH 8.0
Output: {"cpes": ["cpe:2.3:a:lighttpd:lighttpd:1.4.35:*:*:*:*:*:*:*", "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*"]}

EXAMPLE 2 (weak evidence → abstain):
Input: Port 8080/tcp http, no banner, OS detection: <50% confidence
Output: {"cpes": []}

EXAMPLE 3 (mixed evidence → selective):
Input: Port 22/tcp: OpenSSH 8.0, OS detection: Linux 3.X (92%), MAC vendor: CommScope
Output: {"cpes": ["cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:3.*:*:*:*:*:*:*:*"]}

Rules:
- Generate CPEs for hardware (h), OS/firmware (o), and applications (a) you can confidently identify
- Vendor and product are required — omit a CPE entirely if you cannot identify both with confidence
- Use * for version if uncertain; do not guess
- Use * for unknown fields, - for not applicable
- End the response with exactly one JSON object: {"cpes": ["cpe:2.3:...", ...]}

CPE format:
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

COMMON ERRORS TO AVOID:
- "lighttpd" banner does NOT imply hardware vendor—only output application CPE
- MAC vendor alone does NOT mean the OS is vendor-made
- Generic "Linux" OS detection does NOT justify a specific distribution CPE without banner evidence
- Do not output the same component twice (e.g., both linux_kernel:3.2 and linux_kernel:*)""",
    }, 
    {
        "name":    "conversational-kind",
        "version": "1.0",
        "notes":   "Casual tone, clear instructions given in a human like fashion",
        "text":    """Hey, I have this nmap scan data that I need your help with. Could you fingerprint the device and make a CPE for me?
End your response with a JSON object: {"cpes": ["cpe:2.3:...", ...]}""",
    },
]


def now():
    return datetime.now(timezone.utc).isoformat()


def upsert_prompt(db, name, version, text, notes):
    existing = db.prompts.find_one({"prompt_name": name, "prompt_version": version})

    if existing:
        db.prompts.update_one(
            {"_id": existing["_id"]},
            {"$set": {"prompt_text": text, "notes": notes}},
        )
        print(f"  UPDATE  id={existing['_id']}  {name} v{version}")
        return existing["_id"]

    new_id = next_id(db, "prompts")
    db.prompts.insert_one({
        "_id":            new_id,
        "prompt_name":    name,
        "prompt_version": version,
        "prompt_text":    text,
        "notes":          notes,
        "created_at":     now(),
    })
    print(f"  INSERT  id={new_id}  {name} v{version}")
    return new_id


def list_prompts(db):
    rows = list(db.prompts.find({}, {"prompt_name": 1, "prompt_version": 1, "notes": 1}).sort("_id"))
    if not rows:
        print("(no prompts in DB)")
        return
    for row in rows:
        print(f"  id={row['_id']}  {row['prompt_name']} v{row['prompt_version']}  — {row.get('notes') or ''}")


def main():
    parser = argparse.ArgumentParser(description="Seed the prompts collection")
    parser.add_argument("--list", action="store_true", help="Show current prompts and exit")
    args = parser.parse_args()

    ensure_db()
    db = get_db()

    if args.list:
        list_prompts(db)
        return

    for p in PROMPTS:
        upsert_prompt(db, p["name"], p["version"], p["text"], p["notes"])

    print("\nDone. Use `python seed_prompts.py --list` to see all prompts and their IDs.")


if __name__ == "__main__":
    main()
