#!/usr/bin/env python3
"""
Ingest a single nmap XML file into the database.

Creates a device (if new) and writes one scans document containing the scan
metadata, the raw XML, the parsed nmap data, and the plain-text payload that
gets fed to the LLM.

Usage:
    python ingest.py <xml_file> <device_code>
    python ingest.py scans/192.168.1.1_20260413/01-sv-osc-top1000.xml linksys-wrt54gs
    python ingest.py scans/192.168.1.1_20260413/01-sv-osc-top1000.xml linksys-wrt54gs --operator alice --network lab-vlan42
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from db import ensure_db, get_db, next_id


PARSER_VERSION = "1.0"


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
            "os_cpes":      [],
            "services":     [],
            "host_scripts": {},
            "pre_scripts":  pre_scripts,
            "post_scripts": post_scripts,
        }

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
                for osclass in osmatch.findall("osclass"):
                    attr_cpe = osclass.get("cpe")
                    if attr_cpe and attr_cpe not in device["os_cpes"]:
                        device["os_cpes"].append(attr_cpe.strip())
                    for cpe_elem in osclass.findall("cpe"):
                        if cpe_elem.text:
                            txt = cpe_elem.text.strip()
                            if txt and txt not in device["os_cpes"]:
                                device["os_cpes"].append(txt)

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
# Plain text formatter — the payload fed to the LLM
# ---------------------------------------------------------------------------

def format_plaintext(device_code, host, scan_name):
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
    db = get_db()

    xml_string = xml_path.read_text(encoding="utf-8")
    try:
        scan_meta, host = parse_nmap_xml(xml_string)
    except ET.ParseError as e:
        print(f"  SKIP  malformed/truncated XML: {xml_path} ({e})")
        sys.exit(0)

    if host is None:
        print(f"  SKIP  no hosts with state=up in XML: {xml_path}")
        sys.exit(0)

    scan_name = xml_path.stem

    # Device — create if new, otherwise reuse existing
    existing = db.devices.find_one({"device_code": args.device_code}, {"_id": 1})
    if existing:
        device_id = existing["_id"]
        print(f"  device  exists  id={device_id}  ({args.device_code})")
    else:
        device_id = next_id(db, "devices")
        db.devices.insert_one({
            "_id":          device_id,
            "device_code":  args.device_code,
            "mac":          host["mac"],
            "manufacturer": host["vendor"],
            "created_at":   datetime.now(timezone.utc).isoformat(),
        })
        print(f"  device  created id={device_id}  ({args.device_code})")

    # Scan — one document holds session meta, nmap raw+parsed, and the LLM payload
    scan_id = next_id(db, "scans")
    payload = format_plaintext(args.device_code, host, scan_name)

    db.scans.insert_one({
        "_id":            scan_id,
        "device_id":      device_id,
        "target_ip":      host["ip"],
        "hostname":       host["hostname"],
        "network_name":   args.network,
        "operator":       args.operator,
        "started_at":     scan_meta["start_time"],
        "ended_at":       scan_meta["end_time"],
        "nmap": {
            "scan_name":    scan_name,
            "command":      scan_meta["command"],
            "nmap_version": scan_meta["nmap_version"],
            "exit_code":    scan_meta["exit_code"],
            "xml":          xml_string,
            "parsed":       host,
        },
        "payload":         payload,
        "parser_version":  PARSER_VERSION,
    })
    print(f"  scan    created id={scan_id}  ({scan_name})")
    print(f"\n  device_id={device_id}  scan_id={scan_id}")


if __name__ == "__main__":
    main()
