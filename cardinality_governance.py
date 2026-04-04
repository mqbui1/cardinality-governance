#!/usr/bin/env python3
"""
Metric Cardinality Governance for Splunk Observability Cloud

Scans an org for MTS explosions, attributes cost to teams/services,
and uses Claude to recommend rollups and fixes.

Usage:
  python3 cardinality_governance.py scan
  python3 cardinality_governance.py report
  python3 cardinality_governance.py watch
  python3 cardinality_governance.py rollup --metric <name>
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REALM  = os.environ.get("SPLUNK_REALM", "us1")
TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN", "")

API_BASE    = f"https://api.{REALM}.signalfx.com"
INGEST_BASE = f"https://ingest.{REALM}.signalfx.com"

BEDROCK_PROFILE = "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7"

# Thresholds
CRITICAL_MTS_COUNT    = 10_000   # single metric MTS count — critical
HIGH_MTS_COUNT        = 1_000    # single metric MTS count — high
MEDIUM_MTS_COUNT      = 500      # single metric MTS count — medium
CRITICAL_DIM_VALUES   = 10_000   # unique values for a single dimension — critical
HIGH_DIM_VALUES       = 1_000    # unique values for a single dimension — high

# Regex patterns that indicate high-cardinality anti-patterns
CARDINALITY_PATTERNS = [
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "UUID"),
    (re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),                                   "IP address"),
    (re.compile(r"^\d{10,13}$"),                                                              "Timestamp/epoch"),
    (re.compile(r"^[0-9a-f]{32}$", re.I),                                                    "MD5 hash"),
    (re.compile(r"^[0-9a-f]{40}$", re.I),                                                    "SHA1 hash"),
    (re.compile(r".{100,}"),                                                                  "Very long string"),
]

REPORTS_DIR = Path("reports")

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(path, params=None):
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}
    resp = requests.get(f"{API_BASE}{path}", headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def api_post(path, body):
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}
    resp = requests.post(f"{API_BASE}{path}", headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()


def ingest_event(event_type, dimensions, properties):
    if not INGEST_TOKEN:
        return
    headers = {"X-SF-TOKEN": INGEST_TOKEN, "Content-Type": "application/json"}
    payload = [{
        "eventType": event_type,
        "dimensions": dimensions,
        "properties": properties,
        "timestamp": int(time.time() * 1000),
    }]
    try:
        requests.post(f"{INGEST_BASE}/v2/event", headers=headers, json=payload, timeout=10)
    except Exception:
        pass


def execute_signalflow(program, duration_ms=60000):
    """Execute a SignalFlow program and return last values."""
    url = f"https://stream.{REALM}.signalfx.com/v2/signalflow/execute"
    params = {
        "start": int(time.time() * 1000) - duration_ms,
        "stop":  int(time.time() * 1000),
        "immediate": "true",
    }
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "text/plain"}
    try:
        resp = requests.post(url, headers=headers, params=params, data=program, timeout=30, stream=True)
        results = {}
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") == "data":
                    for tsid, val in msg.get("data", {}).items():
                        if val is not None:
                            results[tsid] = val
            except Exception:
                continue
        return results
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Claude helper
# ---------------------------------------------------------------------------

def call_claude(prompt):
    client = boto3.client("bedrock-runtime", region_name="us-west-2")
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = client.invoke_model(modelId=BEDROCK_PROFILE, body=json.dumps(body))
    return json.loads(resp["body"].read())["content"][0]["text"]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def fetch_org_info():
    """Get org-level MTS usage."""
    try:
        return api_get("/v2/organization")
    except Exception as e:
        print(f"  Warning: could not fetch org info: {e}")
        return {}


def fetch_tokens():
    """Fetch org tokens to map ingest source → team."""
    try:
        result = api_get("/v2/token", params={"limit": 100})
        return result.get("results", [])
    except Exception:
        return []


def fetch_metrics(limit=200):
    """Fetch all custom metrics."""
    try:
        result = api_get("/v2/metric", params={"limit": limit})
        return result.get("results", [])
    except Exception as e:
        print(f"  Warning: could not fetch metrics: {e}")
        return []


def fetch_mts_for_metric(metric_name, limit=10000):
    """Fetch MTS count and sample dimensions for a metric."""
    try:
        result = api_get("/v2/metrictimeseries", params={
            "query": f"sf_metric:{metric_name}",
            "limit": limit,
        })
        return result.get("results", [])
    except Exception:
        return []


def search_metrics_by_query(query="*", limit=200):
    """Search metrics matching a query."""
    try:
        result = api_get("/v2/metric", params={"query": query, "limit": limit})
        return result.get("results", [])
    except Exception:
        return []


def detect_cardinality_pattern(value):
    """Return pattern name if value matches a high-cardinality anti-pattern."""
    for pattern, name in CARDINALITY_PATTERNS:
        if pattern.match(str(value)):
            return name
    return None


def analyze_dimensions(mts_list):
    """
    Given a list of MTS objects, find high-cardinality dimensions.
    Returns dict: dim_name -> {count, sample_values, pattern}
    """
    dim_values = defaultdict(set)
    skip_dims = {"sf_metric", "sf_type", "_sf_organizationID", "sf_originatingMetric"}

    for mts in mts_list:
        for dim, val in mts.get("dimensions", {}).items():
            if dim in skip_dims:
                continue
            dim_values[dim].add(str(val))

    results = {}
    for dim, values in dim_values.items():
        count = len(values)
        if count < 10:
            continue
        samples = list(values)[:5]
        pattern = None
        for v in samples:
            p = detect_cardinality_pattern(v)
            if p:
                pattern = p
                break
        results[dim] = {
            "unique_values": count,
            "sample_values": samples,
            "pattern": pattern,
        }

    return dict(sorted(results.items(), key=lambda x: -x[1]["unique_values"]))


def severity(mts_count):
    if mts_count >= CRITICAL_MTS_COUNT:
        return "CRITICAL"
    elif mts_count >= HIGH_MTS_COUNT:
        return "HIGH"
    elif mts_count >= MEDIUM_MTS_COUNT:
        return "MEDIUM"
    return "LOW"


def attribute_to_team(mts_list, tokens):
    """Best-effort attribution: look for service.name or token dimensions."""
    services = set()
    for mts in mts_list[:100]:
        dims = mts.get("dimensions", {})
        for key in ["service.name", "service", "sf_service", "team", "owner"]:
            if key in dims:
                services.add(dims[key])
    return sorted(services) if services else ["unknown"]


def scan_org(top_n=50, verbose=False):
    """
    Full org scan. Returns list of findings sorted by MTS count descending.
    """
    print(f"\nScanning org (realm={REALM})...\n")

    org = fetch_org_info()
    tokens = fetch_tokens()

    token_map = {t.get("name", ""): t for t in tokens}

    # Fetch metrics
    print("  Fetching metric catalog...")
    metrics = fetch_metrics(limit=200)

    if not metrics:
        print("  No metrics found. Check your token permissions.")
        return []

    print(f"  Found {len(metrics)} metrics. Analyzing top offenders...\n")

    findings = []

    for i, metric in enumerate(metrics):
        name = metric.get("name", "")
        mtype = metric.get("type", "gauge")
        custom = metric.get("custom", True)

        if verbose:
            print(f"  [{i+1}/{len(metrics)}] {name}")

        # Fetch MTS for this metric
        mts_list = fetch_mts_for_metric(name, limit=10000)
        mts_count = len(mts_list)

        if mts_count == 0:
            continue

        sev = severity(mts_count)
        if sev == "LOW" and not verbose:
            continue

        # Analyze dimensions
        dim_analysis = analyze_dimensions(mts_list)
        attributed_to = attribute_to_team(mts_list, tokens)

        # Find worst offending dimension
        worst_dim = None
        worst_dim_info = None
        for dim, info in dim_analysis.items():
            if worst_dim is None or info["unique_values"] > worst_dim_info["unique_values"]:
                worst_dim = dim
                worst_dim_info = info

        findings.append({
            "metric":         name,
            "type":           mtype,
            "custom":         custom,
            "mts_count":      mts_count,
            "severity":       sev,
            "dimensions":     dim_analysis,
            "worst_dim":      worst_dim,
            "worst_dim_info": worst_dim_info,
            "attributed_to":  attributed_to,
        })

    # Sort by MTS count descending
    findings.sort(key=lambda x: -x["mts_count"])
    return findings[:top_n]


# ---------------------------------------------------------------------------
# Claude analysis
# ---------------------------------------------------------------------------

def generate_remediation(finding):
    """Use Claude to generate a specific remediation recommendation."""
    dim_summary = ""
    for dim, info in list(finding["dimensions"].items())[:5]:
        pattern_note = f" (looks like {info['pattern']})" if info["pattern"] else ""
        dim_summary += f"  - {dim}: {info['unique_values']} unique values{pattern_note}, e.g. {info['sample_values'][:3]}\n"

    prompt = f"""You are a Splunk Observability Cloud expert specializing in metric cardinality optimization.

A customer has a metric with a cardinality problem:

Metric: {finding['metric']}
Type: {finding['type']}
Custom metric: {finding['custom']}
Total MTS count: {finding['mts_count']}
Severity: {finding['severity']}
Attributed to services/teams: {', '.join(finding['attributed_to'])}

High-cardinality dimensions:
{dim_summary}

Provide a concise remediation recommendation that includes:
1. Root cause (1 sentence — which dimension is the problem and why)
2. Recommended fix (be specific: OTel SDK attribute filter config, SignalFlow rollup, or metric rename)
3. A concrete SignalFlow rollup example if applicable (using data() and sum(by=[...]))
4. Estimated MTS reduction if fix is applied

Be direct and actionable. No preamble. Format as plain text with numbered sections."""

    return call_claude(prompt)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(findings, use_claude=True):
    """Generate a Markdown report from findings."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outpath = REPORTS_DIR / f"cardinality_report_{ts}.md"

    total_mts = sum(f["mts_count"] for f in findings)
    critical   = [f for f in findings if f["severity"] == "CRITICAL"]
    high       = [f for f in findings if f["severity"] == "HIGH"]
    medium     = [f for f in findings if f["severity"] == "MEDIUM"]

    lines = []
    lines.append(f"# Metric Cardinality Governance Report")
    lines.append(f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Realm:** {REALM}")
    lines.append(f"**Metrics analyzed:** {len(findings)}")
    lines.append(f"**Total MTS across findings:** {total_mts:,}")
    lines.append(f"\n## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 CRITICAL (≥{CRITICAL_MTS_COUNT:,} MTS) | {len(critical)} |")
    lines.append(f"| 🟠 HIGH (≥{HIGH_MTS_COUNT:,} MTS)     | {len(high)} |")
    lines.append(f"| 🟡 MEDIUM (≥{MEDIUM_MTS_COUNT:,} MTS)   | {len(medium)} |")

    lines.append(f"\n## Top Offenders\n")
    lines.append(f"| Rank | Metric | MTS Count | Severity | Worst Dimension | Attributed To |")
    lines.append(f"|------|--------|-----------|----------|----------------|---------------|")
    for i, f in enumerate(findings[:20], 1):
        worst = f["worst_dim"] or "—"
        worst_count = f["worst_dim_info"]["unique_values"] if f["worst_dim_info"] else 0
        teams = ", ".join(f["attributed_to"][:2])
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        lines.append(f"| {i} | `{f['metric']}` | {f['mts_count']:,} | {sev_icon} {f['severity']} | `{worst}` ({worst_count:,} values) | {teams} |")

    lines.append(f"\n## Detailed Findings\n")

    for i, f in enumerate(findings, 1):
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        lines.append(f"### {i}. `{f['metric']}` — {sev_icon} {f['severity']}")
        lines.append(f"\n- **MTS count:** {f['mts_count']:,}")
        lines.append(f"- **Metric type:** {f['type']} ({'custom' if f['custom'] else 'builtin'})")
        lines.append(f"- **Attributed to:** {', '.join(f['attributed_to'])}")

        if f["dimensions"]:
            lines.append(f"\n**High-cardinality dimensions:**\n")
            lines.append(f"| Dimension | Unique Values | Pattern | Sample Values |")
            lines.append(f"|-----------|--------------|---------|---------------|")
            for dim, info in list(f["dimensions"].items())[:8]:
                pattern = info["pattern"] or "—"
                samples = ", ".join(f"`{v}`" for v in info["sample_values"][:3])
                lines.append(f"| `{dim}` | {info['unique_values']:,} | {pattern} | {samples} |")

        if use_claude and f["severity"] in ("CRITICAL", "HIGH"):
            print(f"  Generating AI remediation for {f['metric']}...")
            remediation = generate_remediation(f)
            lines.append(f"\n**AI Remediation Recommendation:**\n")
            lines.append(f"```\n{remediation}\n```")

        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by Metric Cardinality Governance — Splunk Observability Cloud*")

    report_text = "\n".join(lines)
    outpath.write_text(report_text)
    return outpath, report_text


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------

def watch_mode(interval=300, threshold=HIGH_MTS_COUNT):
    """Continuously poll for new cardinality explosions and emit events."""
    print(f"\nWatch mode (interval={interval}s, threshold={threshold:,} MTS)\n")
    known = {}

    while True:
        findings = scan_org(top_n=100, verbose=False)
        for f in findings:
            key = f["metric"]
            prev_count = known.get(key, 0)
            curr_count = f["mts_count"]

            # New explosion or >50% growth
            if prev_count == 0 and curr_count >= threshold:
                print(f"  [NEW EXPLOSION] {key}: {curr_count:,} MTS ({f['severity']})")
                ingest_event(
                    "cardinality.explosion.detected",
                    {"metric": key, "realm": REALM},
                    {
                        "mts_count":     curr_count,
                        "severity":      f["severity"],
                        "worst_dim":     f["worst_dim"] or "",
                        "attributed_to": ",".join(f["attributed_to"]),
                    }
                )
            elif prev_count > 0 and curr_count > prev_count * 1.5:
                pct = int((curr_count - prev_count) / prev_count * 100)
                print(f"  [GROWTH +{pct}%] {key}: {prev_count:,} → {curr_count:,} MTS")
                ingest_event(
                    "cardinality.explosion.growing",
                    {"metric": key, "realm": REALM},
                    {
                        "mts_count":      curr_count,
                        "prev_mts_count": prev_count,
                        "growth_pct":     pct,
                        "severity":       f["severity"],
                    }
                )

            known[key] = curr_count

        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Scan complete. {len(findings)} findings. Sleeping {interval}s...")
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Rollup suggestion
# ---------------------------------------------------------------------------

def suggest_rollup(metric_name):
    """Generate a SignalFlow rollup suggestion for a specific metric."""
    mts_list = fetch_mts_for_metric(metric_name, limit=10000)
    if not mts_list:
        print(f"No MTS found for metric '{metric_name}'")
        return

    mts_count = len(mts_list)
    dim_analysis = analyze_dimensions(mts_list)

    print(f"\nMetric: {metric_name}")
    print(f"MTS count: {mts_count:,}")
    print(f"\nDimensions:")
    for dim, info in dim_analysis.items():
        pattern = f" [{info['pattern']}]" if info["pattern"] else ""
        print(f"  {dim}: {info['unique_values']:,} unique values{pattern}")

    print(f"\nGenerating rollup recommendations...\n")

    # Build list of safe (low-cardinality) dimensions to keep
    safe_dims = [d for d, info in dim_analysis.items() if info["unique_values"] <= 50]
    noisy_dims = [d for d, info in dim_analysis.items() if info["unique_values"] > 50]

    prompt = f"""You are a SignalFlow and Splunk Observability Cloud expert.

Metric: {metric_name}
Total MTS: {mts_count:,}

All dimensions with cardinality:
{json.dumps(dim_analysis, indent=2, default=str)}

Safe dimensions to keep (low cardinality): {safe_dims}
Noisy dimensions to drop/aggregate (high cardinality): {noisy_dims}

Generate:
1. The recommended SignalFlow rollup (using data() with sum(by=[...]) keeping only safe dims)
2. An OTel Collector processor config snippet to drop the noisy dimensions at collection time
3. A brief explanation of the expected MTS reduction

Return ONLY the content, no preamble."""

    result = call_claude(prompt)
    print(result)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Metric Cardinality Governance for Splunk Observability Cloud")
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan org for cardinality issues")
    p_scan.add_argument("--top", type=int, default=20, help="Show top N metrics (default: 20)")
    p_scan.add_argument("--verbose", action="store_true", help="Show all metrics including LOW severity")

    # report
    p_report = sub.add_parser("report", help="Generate full Markdown report with AI remediation")
    p_report.add_argument("--top", type=int, default=50, help="Analyze top N metrics (default: 50)")
    p_report.add_argument("--no-ai", action="store_true", help="Skip AI remediation (faster)")

    # watch
    p_watch = sub.add_parser("watch", help="Continuously monitor for cardinality explosions")
    p_watch.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    p_watch.add_argument("--threshold", type=int, default=HIGH_MTS_COUNT, help="MTS threshold for alerts")

    # rollup
    p_rollup = sub.add_parser("rollup", help="Generate rollup suggestions for a specific metric")
    p_rollup.add_argument("--metric", required=True, help="Metric name to analyze")

    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    if args.command == "scan":
        findings = scan_org(top_n=args.top, verbose=args.verbose)
        if not findings:
            print("No cardinality issues found.")
            return

        print(f"\n{'Rank':<5} {'Metric':<50} {'MTS':>8} {'Severity':<10} {'Worst Dimension':<30} {'Attributed To'}")
        print("-" * 130)
        for i, f in enumerate(findings, 1):
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
            worst = f"{f['worst_dim']} ({f['worst_dim_info']['unique_values']:,})" if f["worst_dim"] else "—"
            teams = ", ".join(f["attributed_to"][:2])
            print(f"{i:<5} {f['metric']:<50} {f['mts_count']:>8,} {sev_icon+f['severity']:<12} {worst:<30} {teams}")

    elif args.command == "report":
        findings = scan_org(top_n=args.top)
        if not findings:
            print("No cardinality issues found.")
            return
        print(f"\nGenerating report for {len(findings)} findings...")
        outpath, _ = generate_report(findings, use_claude=not args.no_ai)
        print(f"\nReport saved to: {outpath}")

    elif args.command == "watch":
        watch_mode(interval=args.interval, threshold=args.threshold)

    elif args.command == "rollup":
        suggest_rollup(args.metric)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
