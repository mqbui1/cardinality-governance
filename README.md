# Metric Cardinality Governance

Scans a Splunk Observability Cloud org for MTS cardinality explosions, attributes them to teams/services, and uses Claude (AWS Bedrock) to generate specific remediation recommendations.

## Why it matters

High-cardinality metrics are the #1 cause of surprise overage bills in Splunk Observability Cloud. Common culprits: UUIDs as dimensions, user IDs, IP addresses, request IDs embedded in metric labels.

## Modes

| Command | Description |
|---------|-------------|
| `scan` | Quick ranked list of offenders by MTS count |
| `report` | Full Markdown report with AI remediation per metric |
| `watch` | Continuous polling — emits Splunk events on new explosions |
| `rollup` | Generate SignalFlow rollup + OTel processor config for one metric |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SPLUNK_ACCESS_TOKEN=<your-token>
export SPLUNK_REALM=us1
export SPLUNK_INGEST_TOKEN=<your-ingest-token>   # optional, for watch mode events
export AWS_DEFAULT_REGION=us-west-2               # for Bedrock (AI remediation)
```

## Usage

```bash
# Quick scan — top 20 metrics by MTS count
python3 cardinality_governance.py scan

# Full report with AI remediation (saved to reports/)
python3 cardinality_governance.py report

# Report without AI (faster, no Bedrock needed)
python3 cardinality_governance.py report --no-ai

# Watch mode — poll every 5 minutes, emit events on explosions
python3 cardinality_governance.py watch --interval 300

# Deep-dive on a specific metric
python3 cardinality_governance.py rollup --metric my.custom.metric
```

## Severity thresholds

| Severity | MTS Count |
|----------|-----------|
| 🔴 CRITICAL | ≥ 10,000 |
| 🟠 HIGH | ≥ 1,000 |
| 🟡 MEDIUM | ≥ 500 |

## Detection patterns

Automatically flags dimensions whose values look like:
- UUIDs (`550e8400-e29b-41d4-a716-...`)
- IP addresses (`192.168.1.1`)
- Timestamps / epoch values (`1712345678`)
- MD5/SHA1 hashes
- Unusually long strings (>100 chars)

## Event types (watch mode)

| Event | Description |
|-------|-------------|
| `cardinality.explosion.detected` | New metric crosses threshold |
| `cardinality.explosion.growing` | Existing metric grew >50% since last scan |
