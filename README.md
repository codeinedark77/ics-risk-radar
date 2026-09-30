# ics-risk-radar

Defensive risk assessment for OT/ICS (Operational Technology / Industrial
Control System) environments. Scores assets, zones, and conduits against a
rule catalogue of publicly documented risk categories, maps findings to
IEC 62443 / NIST SP 800-82 control families, cross-checks zone/asset
criticality topology, and includes a protocol-agnostic statistical
anomaly detector for telemetry time series -- now wired straight into
the report and CLI.

**Status: cold-verified.** 77/77 tests passing, 99% statement coverage
(run fresh in a clean venv — see below). This was built standalone; it has
**not** been checked against any existing `ics-risk-radar` / `OT/ICS risk
radar` code you may already have. Diff before merging.

## v0.2.0 additions

- **9-rule catalogue** (was 7): added `ICS-006` (no patch date on record)
  and `ICS-007` (proprietary/undocumented protocol in use).
- **Topology checks** (`topology.py`, new): cross-cutting rule `ICS-201`
  flags an asset whose own criticality outranks the zone it's declared to
  sit in -- a mis-zoning signal the old per-subject rules couldn't catch
  because they only ever looked at one asset or conduit in isolation.
- **Anomaly detection is now wired in.** `build_report(inventory,
  telemetry={...})` and `ics-risk-radar scan ... --telemetry file.json`
  run the existing `RollingZScoreDetector` per asset and fold results
  into the report's new `anomalies` key.
- **SARIF 2.1.0 export** (`sarif.py`, new): `to_sarif()` /
  `write_sarif()` / `ics-risk-radar scan ... --sarif-out findings.sarif`.
  Matches Sieve's existing SARIF output format so both can feed one
  downstream dashboard.

## Scope, on purpose

This is assessment and scoring logic over **user-supplied metadata and
numeric telemetry**. It contains:

- No protocol client code (no Modbus/DNP3/IEC 61850 packet crafting)
- No code that connects to or sends commands to real field devices
- No exploit payloads — risk rules encode *categories* of known-risky
  configuration (e.g. "protocol has no native authentication", "asset is
  internet-facing"), each backed by public standards guidance, not attack
  techniques

If you extend this toward live network capture, that's a deliberate
next step you take with your own review — not something this package
does on its own.

## Install

```bash
pip install -e .
```

Requires Python 3.10+, `pydantic>=2.4`, `PyYAML>=6.0`.

## Quick start

```bash
ics-risk-radar scan sample_data/sample_inventory.yaml
# or write to a file:
ics-risk-radar scan sample_data/sample_inventory.yaml --out report.json
```

Or from Python:

```python
from ics_risk_radar import AssetInventory, RiskEngine, build_report

inv = AssetInventory.from_yaml("sample_data/sample_inventory.yaml")
engine = RiskEngine(inv)
print(engine.score_assets())
print(build_report(inv))
```

## Modules

| Module | Purpose |
|---|---|
| `models.py` | Pydantic models: `Zone`, `Conduit`, `Asset`, `Finding`, `RiskScore` (IEC 62443 zone/conduit vocabulary) |
| `inventory.py` | `AssetInventory` — register zones/conduits/assets, load from YAML |
| `risk_rules.py` | Rule catalogue (`ICS-001`..`ICS-102`) — defensive, metadata-only |
| `risk_engine.py` | `RiskEngine` — turns findings into 0-100 scores with a severity band, weakest-link zone scoring |
| `compliance.py` | Maps rule IDs to IEC 62443-3-3 / NIST SP 800-82 control families |
| `anomaly.py` | `RollingZScoreDetector` — flags numeric telemetry samples that deviate from a rolling baseline |
| `topology.py` | `evaluate_topology()` — cross-cutting checks needing full-inventory context (`ICS-201`) |
| `sarif.py` | `to_sarif()` / `write_sarif()` — SARIF 2.1.0 output, matching Sieve's format |
| `report.py` | Builds/writes the JSON assessment report, with optional telemetry → anomalies |
| `cli.py` | `ics-risk-radar scan <inventory.yaml> [--telemetry f.json] [--sarif-out f.sarif]` |

## Integration points (for manual merging)

- **Real asset data**: replace `sample_data/sample_inventory.yaml` with your
  actual inventory, or write a loader for whatever source you already have
  (CMDB export, Neo4j graph, spreadsheet) that constructs an `AssetInventory`
  the same way `from_yaml` does.
- **Telemetry still has to come from you.** `--telemetry file.json` expects
  `{"asset_id": [numbers...]}` you've already extracted from wherever you
  capture packet rate / cycle time / whatever signal you're tracking — this
  package still has no network capture code of its own, by design.
- **Rule catalogue is intentionally scoped (9 rules).** It's structured so
  adding a rule is one `Rule(...)` entry in `risk_rules.py` plus one line in
  `compliance.py` (or, for a rule that needs whole-inventory context like
  `ICS-201`, a new check in `topology.py`) — extend it against your actual
  fleet's real risk factors rather than a wish list.

## Known limitations (honest, not hedged)

- Rule catalogue covers common categories, not an exhaustive CVE database —
  it will not tell you about a specific unpatched CVE, only that firmware is
  behind the version you told it was latest.
- Firmware "latest known" version has to be supplied by you; this package
  does not phone home to any vendor advisory feed.
- Anomaly detector is a single method (rolling z-score). It's a reasonable
  general-purpose baseline, not a replacement for protocol-aware IDS. A
  perfectly flat baseline followed by any deviation produces a very large
  (not infinite, but not meaningfully bounded) z-score by design -- treat
  it as "flagged", not as a magnitude to graph directly.
- No persistence layer — this reads a YAML file and produces a report; it
  does not track findings over time the way Chronicle tracks audit history.
- `ICS-201` (topology) only checks asset-vs-zone criticality. It does not
  yet check conduit paths that skip an intermediate zone (e.g. IT straight
  to Level 1 control) -- that needs a zone-hierarchy concept this package
  doesn't model yet.

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
python -m pytest tests/ --cov=ics_risk_radar --cov-report=term-missing
```

77 tests, 99% statement coverage as of this build (4 lines uncovered are an
`argparse` error path, an inventory edge branch, and a risk-engine zone
edge branch — not load-bearing logic).
