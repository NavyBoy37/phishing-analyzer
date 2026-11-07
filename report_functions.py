"""
report_functions.py - prints the analysis and writes it out as JSON.
"""

import json


def _section(title):
    print()
    print(title)
    print("-" * len(title))


def print_report(parsed, result, iocs):
    print()
    print("=" * 78)
    print(f"{parsed['file']}:  {result['verdict']}  (score {result['score']})")
    print("=" * 78)
    print(f"Subject:     {parsed['subject']}")
    print(f"From:        {parsed['from_name']} <{parsed['from_address']}>")
    if parsed["reply_to"]:
        print(f"Reply-To:    {', '.join(parsed['reply_to'])}")
    if parsed["return_path"]:
        print(f"Return-Path: {parsed['return_path']}")
    auth = parsed["auth"]
    print(f"Auth:        SPF={auth['spf']}  DKIM={auth['dkim']}  DMARC={auth['dmarc']}")

    _section("Why")
    if not result["hits"]:
        print("  No checks fired.")
    for h in sorted(result["hits"], key=lambda h: -h["weight"]):
        print(f"  +{h['weight']:<3} {h['check']:<22} {h['detail']}")

    _section("Relay path (oldest first)")
    for number, hop in enumerate(parsed["received"], 1):
        print(f"  {number}. {hop['from'] or '?'}  {' '.join(hop['ips'])}")

    if parsed["attachments"]:
        _section("Attachments")
        for a in parsed["attachments"]:
            print(f"  {a['filename']}  ({a['content_type']}, {a['size']} bytes)")
            print(f"    sha256 {a['sha256']}")

    _section("IOCs")
    print("  domains:  " + (", ".join(iocs["domains"]) or "none"))
    print("  relay IPs: " + (", ".join(iocs["relay_ips"]) or "none"))


def write_json(reports, path):
    with open(path, "w", encoding="utf-8") as json_file:
        json.dump(reports, json_file, indent=2)
    print()
    print("Wrote " + path)
