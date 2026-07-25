#!/usr/bin/env python3
"""
Bulk-create Metrics Pipeline Management (MPM) "Drop" rulesets from a customer-
provided metrics list, via the Splunk Observability Cloud metric_ruleset API:

  POST /v2/metricruleset
  https://dev.splunk.com/observability/reference/api/metric_ruleset/latest#endpoint-create-new-metric-ruleset

Each row's "Metric name" becomes a ruleset with routingRule.destination = "Drop".
The actual HTTP call is made with `curl` (per engineering's instruction), invoked
as a subprocess for each metric. This script handles parsing the customer's xlsx
export, building each request body, looping with rate-limiting, and logging a
full audit trail to reports/.

DEFAULT MODE IS DRY RUN. No API calls are made unless --execute is passed.
Dropping a metric stops real-time ingestion for it going forward — this is not
casually reversible (a restoration job only replays *archived* data, and only
if destination was "Archived", not "Drop"). Review the dry-run output first.

Usage:
  # 1. Dry run — parses the xlsx, prints what would be sent, no API calls
  python3 drop_metrics_mpm.py --file metricsOverview_2026-07-10_20-26-33.xlsx

  # 2. Test on a handful of metrics first
  python3 drop_metrics_mpm.py --file metricsOverview_2026-07-10_20-26-33.xlsx --execute --limit 5

  # 3. Full run
  python3 drop_metrics_mpm.py --file metricsOverview_2026-07-10_20-26-33.xlsx --execute

Env vars:
  SPLUNK_ACCESS_TOKEN   Org API access token (org admin scope required to create rulesets)
  SPLUNK_REALM          e.g. us0, us1, us2, eu0 (default: us1)
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path

REALM = os.environ.get("SPLUNK_REALM", "us1")
TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = os.environ.get("SPLUNK_API_BASE", f"https://api.{REALM}.signalfx.com")

REPORTS_DIR = Path("reports")

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def read_metric_names(xlsx_path):
    """Parse the 'Metric name' column out of the MPM metrics-overview xlsx export.
    Pure stdlib (zipfile + ElementTree) — no openpyxl dependency required."""
    z = zipfile.ZipFile(xlsx_path)
    sst_root = ET.fromstring(z.read("xl/sharedStrings.xml"))
    shared = ["".join((t.text or "") for t in si.findall(".//m:t", NS)) for si in sst_root.findall("m:si", NS)]
    sheet_root = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    rows = sheet_root.find("m:sheetData", NS).findall("m:row", NS)

    def cell_value(c):
        v = c.find("m:v", NS)
        if v is None:
            return None
        return shared[int(v.text)] if c.get("t") == "s" else v.text

    header = [cell_value(c) for c in rows[0].findall("m:c", NS)]
    idx = header.index("Metric name")

    names = []
    for r in rows[1:]:
        vals = [cell_value(c) for c in r.findall("m:c", NS)]
        if idx < len(vals) and vals[idx]:
            names.append(vals[idx])
    return names


def build_payload(metric_name):
    return {
        "metricName": metric_name,
        "version": 2,
        "routingRule": {"destination": "Drop"},
    }


def curl_create_ruleset(payload):
    """POST the ruleset via curl. Returns (http_status, response_body)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "-X", "POST",
                f"{API_BASE}/v2/metricruleset",
                "-H", "Content-Type: application/json",
                "-H", f"X-SF-TOKEN: {TOKEN}",
                "-d", f"@{tmp_path}",
                "-w", "\n%{http_code}",
            ],
            capture_output=True, text=True, timeout=30,
        )
    finally:
        os.unlink(tmp_path)

    if result.returncode != 0:
        return None, f"curl failed: {result.stderr.strip()}"

    output = result.stdout.rsplit("\n", 1)
    if len(output) != 2:
        return None, f"unexpected curl output: {result.stdout!r}"
    body, status = output
    return int(status), body.strip()


def classify(status, body):
    if status == 200:
        return "created"
    if status == 409 or "already exists" in body.lower():
        return "skipped_exists"
    return "failed"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", help="Path to the metricsOverview_*.xlsx export")
    ap.add_argument("--metrics", help="Comma-separated metric names, as an alternative to --file (for small ad-hoc tests)")
    ap.add_argument("--execute", action="store_true", help="Actually call the API. Without this flag, dry-run only.")
    ap.add_argument("--limit", type=int, default=None, help="Only process the first N metrics (for testing)")
    ap.add_argument("--sleep", type=float, default=0.3, help="Seconds to sleep between API calls (default 0.3)")
    ap.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt")
    args = ap.parse_args()

    if bool(args.file) == bool(args.metrics):
        sys.exit("Provide exactly one of --file or --metrics")

    if args.metrics:
        names = [m.strip() for m in args.metrics.split(",") if m.strip()]
        source = "--metrics"
    else:
        names = read_metric_names(args.file)
        source = args.file
    if args.limit:
        names = names[: args.limit]

    print(f"Parsed {len(names)} metric name(s) from {source}")

    if not args.execute:
        print("\n--- DRY RUN (no API calls made) ---")
        for n in names[:10]:
            print(json.dumps(build_payload(n)))
        if len(names) > 10:
            print(f"... and {len(names) - 10} more")
        print(f"\nRun again with --execute to actually create {len(names)} Drop ruleset(s).")
        return

    if not TOKEN:
        sys.exit("SPLUNK_ACCESS_TOKEN is not set.")

    if not args.yes:
        resp = input(
            f"\nThis will create {len(names)} MPM Drop ruleset(s) against realm '{REALM}'. "
            f"Metrics will stop real-time ingestion. Type 'yes' to continue: "
        )
        if resp.strip().lower() != "yes":
            print("Aborted.")
            return

    REPORTS_DIR.mkdir(exist_ok=True)
    log_path = REPORTS_DIR / f"mpm_drop_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    created = skipped = failed = 0
    with open(log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric_name", "http_status", "result", "response_body"])

        for i, name in enumerate(names, 1):
            payload = build_payload(name)
            status, body = curl_create_ruleset(payload)
            result = classify(status, body) if status is not None else "failed"

            writer.writerow([name, status, result, body])
            f.flush()

            if result == "created":
                created += 1
            elif result == "skipped_exists":
                skipped += 1
            else:
                failed += 1

            print(f"[{i}/{len(names)}] {name}: {result} (HTTP {status})")
            time.sleep(args.sleep)

    print(f"\nDone. created={created} skipped_exists={skipped} failed={failed}")
    print(f"Full audit log: {log_path}")


if __name__ == "__main__":
    main()
