#!/usr/bin/env python3
"""
Ingest a single nmap XML file into the database.

Creates a device (if new), scan_session, scan_run, and aggregated_input.
Each file gets its own session so different scan types can be run through
the LLM independently.

Usage:
    python ingest.py <xml_file> <device_code>
    python ingest.py scans/192.168.1.1_20260413/01-sv-osc-top1000.xml linksys-wrt54gs
    python ingest.py scans/192.168.1.1_20260413/01-sv-osc-top1000.xml linksys-wrt54gs --operator alice --network lab-vlan42
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from db import ensure_db, get_connection


# ---------------------------------------------------------------------------
# nmap XML parser
# ---------------------------------------------------------------------------

def _collect_scripts(parent):
    """Return {script_id: output} for all <script> children."""
    return {
        s.get("id"): s.get("output", "").strip()
        for s in parent.findall("script")
        if s.get("id") and s.get("output", "").strip()
    }


def _nbstat_name(script_elem):
    m = re.search(r"NetBIOS name:\s*(\S+)", script_elem.get("output", ""))
    return m.group(1) if m else None


def parse_nmap_xml(xml_string):
    """Parse nmap XML and return (scan_meta, host) for the first up host.

    scan_meta: command, nmap version, timestamps.
    host: ip, mac, vendor, hostname, os_guesses, services, scripts.
    Returns (scan_meta, None) if no hosts are up.
    """
    root = ET.fromstring(xml_string)

    scan_meta = {
        "command":      root.get("args"),
        "nmap_version": root.get("version"),
        "start_time":   root.get("startstr"),
        "end_time":     None,
        "exit_code":    None,
    }

    finished = root.find("runstats/finished")
    if finished is not None:
        scan_meta["end_time"]  = finished.get("timestr")
        scan_meta["exit_code"] = int(finished.get("exit") == "success")

    pre_scripts  = _collect_scripts(root.find("prescript")  or ET.Element("x"))
    post_scripts = _collect_scripts(root.find("postscript") or ET.Element("x"))

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        device = {
            "ip":           None,
            "mac":          None,
            "vendor":       None,
            "hostname":     None,
            "os_guesses":   [],
            "services":     [],
            "host_scripts": {},
            "pre_scripts":  pre_scripts,
            "post_scripts": post_scripts,
        }

        # nmap includes vendor from its own OUI lookup in the address element
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                device["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                device["mac"]    = addr.get("addr")
                device["vendor"] = addr.get("vendor")

        if not device["ip"]:
            continue

        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                device["hostname"] = hn.get("name")

        hostscript = host.find("hostscript")
        if hostscript is not None:
            device["host_scripts"] = _collect_scripts(hostscript)
            if not device["hostname"]:
                for s in hostscript.findall("script"):
                    if s.get("id") == "nbstat":
                        device["hostname"] = _nbstat_name(s)
                        break

        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                name     = osmatch.get("name")
                accuracy = osmatch.get("accuracy")
                if name:
                    device["os_guesses"].append(f"{name} ({accuracy}%)" if accuracy else name)

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = {
                    "port":     int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service":  None,
                    "product":  None,
                    "version":  None,
                    "cpes":     [],
                    "scripts":  _collect_scripts(port),
                }
                service = port.find("service")
                if service is not None:
                    svc["service"] = service.get("name")
                    svc["product"] = service.get("product")
                    svc["version"] = service.get("version")
                    svc["cpes"]    = [c.text for c in service.findall("cpe") if c.text]
                device["services"].append(svc)

        return scan_meta, device

    return scan_meta, None


# ---------------------------------------------------------------------------
# Plain text formatter
# ---------------------------------------------------------------------------

def format_plaintext(device_code, host, scan_name):
    """Format parsed host data as plain text for the LLM."""
    lines = []

    lines.append(f"Device: {device_code}")
    lines.append(f"Scan:   {scan_name}")
    lines.append(f"IP:     {host['ip']}")
    lines.append(f"Hostname: {host['hostname'] or 'unknown'}")
    lines.append(f"Vendor (nmap): {host['vendor'] or 'unknown'}")
    lines.append("")

    lines.append("OS Guesses:")
    if host["os_guesses"]:
        for g in host["os_guesses"]:
            lines.append(f"  {g}")
    else:
        lines.append("  (none detected)")
    lines.append("")

    lines.append("Open Ports:")
    if host["services"]:
        for svc in host["services"]:
            port_str    = f"{svc['port']}/{svc['protocol']}"
            service_str = svc["service"] or ""
            product_str = " ".join(filter(None, [svc["product"], svc["version"]]))
            lines.append(f"  {port_str:<12} {service_str:<10} {product_str}")
            if svc["cpes"]:
                for cpe in svc["cpes"]:
                    lines.append(f"    nmap CPE: {cpe}")
            for script_id, output in svc["scripts"].items():
                lines.append(f"    [{script_id}] {output[:200]}")
    else:
        lines.append("  (none)")
    lines.append("")

    if host["host_scripts"]:
        lines.append("Host Scripts:")
        for script_id, output in host["host_scripts"].items():
            lines.append(f"  [{script_id}]")
            lines.append(f"  {output[:500]}")
        lines.append("")

    discovery = {**host["pre_scripts"], **host["post_scripts"]}
    if discovery:
        lines.append("Discovery Scripts:")
        for script_id, output in discovery.items():
            lines.append(f"  [{script_id}]")
            lines.append(f"  {output[:500]}")
        lines.append("")

    all_cpes = [cpe for svc in host["services"] for cpe in svc["cpes"]]
    lines.append("nmap CPE Guesses (all services):")
    if all_cpes:
        for cpe in all_cpes:
            lines.append(f"  {cpe}")
    else:
        lines.append("  (none)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Ingest a single nmap XML file into the database")
    parser.add_argument("xml_file",    help="Path to nmap XML output file")
    parser.add_argument("device_code", help="Short device identifier (e.g. linksys-wrt54gs)")
    parser.add_argument("--operator",  default=None, help="Who ran the scan")
    parser.add_argument("--network",   default=None, help="Network name or VLAN")
    args = parser.parse_args()

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        print(f"ERROR: file not found: {xml_path}")
        sys.exit(1)

    ensure_db()
    con = get_connection()

    xml_string = xml_path.read_text(encoding="utf-8")
    scan_meta, host = parse_nmap_xml(xml_string)

    if host is None:
        print("ERROR: no hosts found with state=up in XML")
        sys.exit(1)

    scan_name = xml_path.stem

    # Device — create if new, otherwise reuse existing
    row = con.execute("SELECT id FROM devices WHERE device_code = ?", (args.device_code,)).fetchone()
    if row:
        device_id = row["id"]
        print(f"  device    exists  id={device_id}  ({args.device_code})")
    else:
        cur = con.execute(
            "INSERT INTO devices (device_code, mac, manufacturer) VALUES (?, ?, ?)",
            (args.device_code, host["mac"], host["vendor"]),
        )
        device_id = cur.lastrowid
        print(f"  device    created id={device_id}  ({args.device_code})")

    # Scan session
    cur = con.execute(
        """
        INSERT INTO scan_sessions
            (device_id, target_ip, hostname, started_at, ended_at, network_name, operator)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            host["ip"],
            host["hostname"],
            scan_meta["start_time"],
            scan_meta["end_time"],
            args.network,
            args.operator,
        ),
    )
    session_id = cur.lastrowid
    print(f"  session   created id={session_id}")

    # Scan run — store raw XML and parsed JSON
    cur = con.execute(
        """
        INSERT INTO scan_runs
            (scan_session_id, scan_name, command, stdout_text, exit_code, tool_name, tool_version, parsed_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            scan_name,
            scan_meta["command"],
            xml_string,
            scan_meta["exit_code"],
            "nmap",
            scan_meta["nmap_version"],
            json.dumps(host),
        ),
    )
    run_id = cur.lastrowid
    print(f"  scan_run  created id={run_id}  ({scan_name})")

    # Aggregated input — plain text for the LLM
    plaintext = format_plaintext(args.device_code, host, scan_name)
    cur = con.execute(
        """
        INSERT INTO aggregated_inputs
            (scan_session_id, variant_name, parser_version, input_payload_json)
        VALUES (?, ?, ?, ?)
        """,
        (session_id, "plain-text", "1.0", plaintext),
    )
    agg_id = cur.lastrowid
    print(f"  agg_input created id={agg_id}")

    con.commit()
    con.close()

    print(f"\n  device_id={device_id}  aggregated_input_id={agg_id}")


if __name__ == "__main__":
    main()
