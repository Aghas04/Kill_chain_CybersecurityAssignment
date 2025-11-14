#!/usr/bin/env python3
"""
gvm_risk_prioritizer.py

Parses a GVM/OpenVAS XML report, links vulnerabilities to assets (assets.csv),
maps CVSS -> Likelihood, computes Risk = Impact * Likelihood, and writes
a prioritized CSV of risks sorted by descending risk score.

Usage:
    python gvm_risk_prioritizer.py --gvm report.xml --assets assets.csv --out prioritized_risks.csv
"""

import csv
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Dict, Optional, Any, List, Tuple
import sys

def read_assets(csv_path: str) -> Dict[str, Dict[str, Any]]:
    """Read assets.csv and return dict keyed by IP address."""
    assets = {}
    with open(csv_path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        required = {'ip_address', 'asset_name', 'asset_owner', 'asset_criticality'}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"assets.csv must contain headers: {', '.join(required)}")
        for row in reader:
            ip = row['ip_address'].strip()
            if not ip:
                continue
            try:
                criticality = int(row['asset_criticality'])
            except Exception:
                criticality = None
            assets[ip] = {
                'asset_name': row.get('asset_name', '').strip(),
                'asset_owner': row.get('asset_owner', '').strip(),
                'asset_criticality': criticality
            }
    return assets

def safe_find_text(elem: ET.Element, *path_parts) -> Optional[str]:
    """Try multiple path pieces in nested structure, return first non-empty text."""
    cur = elem
    for part in path_parts:
        found = cur.find(part)
        if found is not None and (found.text is not None):
            return found.text.strip()
    return None

def extract_cvss_from_nvt(nvt_elem: ET.Element) -> Optional[float]:
    """Look for common CVSS tags under nvt and convert to float if present."""
    for tag in ('cvss_base', 'cvss_base_score', 'cvss3_base_score', 'cvss'):
        node = nvt_elem.find(tag)
        if node is not None and node.text:
            try:
                return float(node.text.strip())
            except Exception:
                pass
    for child in nvt_elem:
        if child.text:
            txt = child.text.strip()
            try:
                val = float(txt)
                return val
            except Exception:
                continue
    return None

def cvss_to_likelihood(cvss: Optional[float]) -> int:
    """
    Map CVSS (0.0-10.0) to Likelihood (1-5).
    Default mapping (adjustable):
      CVSS >= 9.0  -> Likelihood 5 (Critical)
      CVSS >= 7.0  -> Likelihood 4 (High)
      CVSS >= 4.0  -> Likelihood 3 (Medium)
      CVSS > 0.0   -> Likelihood 2 (Low)
      CVSS == 0.0 or None -> Likelihood 1 (Very unlikely / informational)
    """
    if cvss is None:
        return 1
    try:
        c = float(cvss)
    except Exception:
        return 1
    if c >= 9.0:
        return 5
    if c >= 7.0:
        return 4
    if c >= 4.0:
        return 3
    if c > 0.0:
        return 2
    return 1

def parse_gvm_xml(xml_path: str) -> List[Dict[str, Any]]:
    """
    Parse the GVM/OpenVAS XML and return a list of vulnerabilities found with fields:
      - ip (host)
      - name
      - description
      - cvss (float or None)
      - source_element (optional raw element for debugging)
    This parser is tolerant: it searches for 'result' entries, then looks under 'nvt'
    for details.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []

    for result in root.findall('.//result'):
        host = None

        host_elems = result.findall('host')

        if host_elems:
            host = None
            for h in host_elems:
                if 'start' in h.attrib:
                    if h.text and h.text.strip():
                        host = h.text.strip()
                        break


            if not host:
                last = host_elems[-1]
                if last.text:
                    host = last.text.strip()

        if not host:
            host = result.get('host') or result.get('ip')


        nvt = result.find('nvt')
        name = None
        description = None
        cvss = None

        if nvt is not None:
            # name often at nvt/name
            nm = nvt.find('name')
            if nm is not None and nm.text:
                name = nm.text.strip()
            # description often at nvt/description or result/description
            descr = nvt.find('description')
            if descr is not None and descr.text:
                description = descr.text.strip()
            # try CVSS values under nvt
            cvss = extract_cvss_from_nvt(nvt)
        # fallback: result -> name
        if not name:
            name_node = result.find('name')
            if name_node is not None and name_node.text:
                name = name_node.text.strip()

        # fallback: description in result itself
        if not description:
            descr_node = result.find('description')
            if descr_node is not None and descr_node.text:
                description = descr_node.text.strip()

        # Some GVM exports include a 'threat' or other children with CVSS-like info
        if cvss is None:
            # try to find any 'cvss' tag anywhere under result
            node = result.find('.//cvss')
            if node is not None and node.text:
                try:
                    cvss = float(node.text.strip())
                except Exception:
                    cvss = None
        results.append({
            'ip': host,
            'name': name or '(unknown)',
            'description': description or '',
            'cvss': cvss
        })
    return results

def compute_and_link(vulns: List[Dict[str, Any]], assets: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Link parsed vulns to assets, compute likelihood, impact, and risk."""
    output = []
    for v in vulns:
        ip = v.get('ip') or ''
        asset = assets.get(ip, {'asset_name': '(unknown)', 'asset_owner': '', 'asset_criticality': None})
        impact = asset.get('asset_criticality')
        if impact is None:
            # If asset criticality unknown, default to 1 (low) but mark it
            impact = 1
        likelihood = cvss_to_likelihood(v.get('cvss'))
        risk = impact * likelihood
        output.append({
            'ip_address': ip,
            'asset_name': asset.get('asset_name'),
            'asset_owner': asset.get('asset_owner'),
            'asset_criticality': impact,
            'vuln_name': v.get('name'),
            'description': v.get('description'),
            'cvss': v.get('cvss'),
            'likelihood': likelihood,
            'impact': impact,
            'risk_score': risk
        })
    # Sort descending by risk_score, then by likelihood, then cvss
    output.sort(key=lambda x: (x['risk_score'], x['likelihood'], (x['cvss'] or 0.0)), reverse=True)
    return output

def write_prioritized_csv(rows: List[Dict[str, Any]], out_path: str) -> None:
    """Write rows to a CSV with a useful header."""
    fieldnames = [
        'ip_address', 'asset_name', 'asset_owner', 'asset_criticality',
        'vuln_name', 'description', 'cvss', 'likelihood', 'impact', 'risk_score'
    ]
    with open(out_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            # ensure CVSS is written as number or blank
            row = r.copy()
            row['cvss'] = '' if r.get('cvss') is None else r.get('cvss')
            writer.writerow(row)

def main(argv=None):
    parser = argparse.ArgumentParser(description="GVM -> Prioritized Risk list")
    parser.add_argument('--gvm', required=True, help='Path to GVM/OpenVAS XML report')
    parser.add_argument('--assets', required=True, help='Path to assets.csv')
    parser.add_argument('--out', default='risk_register.csv', help='Output CSV path')
    args = parser.parse_args(argv)

    try:
        assets = read_assets(args.assets)
    except Exception as e:
        print(f"Error reading assets file: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        vulns = parse_gvm_xml(args.gvm)
    except Exception as e:
        print(f"Error parsing GVM XML: {e}", file=sys.stderr)
        sys.exit(3)

    linked = compute_and_link(vulns, assets)
    write_prioritized_csv(linked, args.out)

    # Print a short preview (top 10)
    print(f"Wrote {len(linked)} vulnerability rows to {args.out}. Top 10 by risk score:")
    for i, r in enumerate(linked[:10], start=1):
        cvss_str = 'N/A' if r['cvss'] is None else r['cvss']
        print(f"{i:2d}. {r['ip_address']} | Asset: {r['asset_name']} | CVSS: {cvss_str} | "
              f"Impact:{r['impact']} Likelihood:{r['likelihood']} -> Risk:{r['risk_score']} | {r['vuln_name']}")
    print("Done.")

if __name__ == '__main__':
    main()
