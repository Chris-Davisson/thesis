#!/usr/bin/env python3
"""
Run the nmap scan suite against one or more IPs.
Scan definitions are read from config.toml.
Output is saved to scans/<ip>_<timestamp>/<scan_name>.xml

Usage:
    python run_scans.py 192.168.1.1
    python run_scans.py 192.168.1.1 192.168.1.2

Requires admin/root for OS detection (-O) and UDP scans.
"""

import argparse
import subprocess
import sys
import tomllib
from datetime import datetime
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.toml"
SCANS_DIR = Path(__file__).parent / "scans"


def load_config():
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def run_scan(ip: str, name: str, flags: list, out_dir: Path, timeout: int) -> bool:
    xml_path = out_dir / f"{name}.xml"
    cmd = ["nmap"] + list(flags) + ["-oX", str(xml_path), ip]

    print(f"\n{'=' * 70}")
    print(f"  [{name}]")
    print(f"  {' '.join(cmd)}")
    print(f"{'=' * 70}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.stdout:
            for line in result.stdout.strip().splitlines()[-15:]:
                print(f"  {line}")
        if result.returncode != 0:
            print(f"  ** nmap exited with code {result.returncode}")
            if result.stderr:
                print(f"  STDERR: {result.stderr[:300]}")
            return False
        if xml_path.exists():
            print(f"  -> Saved {xml_path} ({xml_path.stat().st_size:,} bytes)")
            return True
        print("  ** XML file not created")
        return False
    except subprocess.TimeoutExpired:
        print(f"  ** Timed out after {timeout}s, skipping")
        return False
    except FileNotFoundError:
        print("  ** nmap not found on PATH. Install nmap first.")
        sys.exit(1)


def main():
    config = load_config()
    scans = [(s["name"], s["flags"], s["timeout"]) for s in config["scans"]]

    parser = argparse.ArgumentParser(description="Run nmap scan suite against target(s)")
    parser.add_argument("ips", nargs="+", help="One or more target IP addresses")
    args = parser.parse_args()

    suite = scans

    print(f"\n** {len(suite)} scans x {len(args.ips)} target(s) = {len(suite) * len(args.ips)} total runs")

    for ip in args.ips:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = SCANS_DIR / f"{ip}_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)

        total = len(suite)
        passed = 0
        failed = 0

        print(f"\n{'#' * 70}")
        print(f"  TARGET: {ip}")
        print(f"  Output: {out_dir}")
        print(f"  Scans:  {total}")
        print(f"{'#' * 70}")

        for name, flags, timeout in suite:
            if run_scan(ip, name, flags, out_dir, timeout):
                passed += 1
            else:
                failed += 1

        print(f"\n{'=' * 70}")
        print(f"  {ip} DONE -- {passed}/{total} succeeded, {failed} failed")
        print(f"  Output: {out_dir}")
        print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
