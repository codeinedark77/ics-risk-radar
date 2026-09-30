"""SARIF 2.1.0 output for findings.

Sieve (the existing secrets/vuln scanner in AI Empire) already emits
SARIF. Giving ics-risk-radar the same output format means both can
feed one downstream SARIF-consuming dashboard, per the integration
note in the README. Findings here are logical (asset/conduit ids),
not file-based, so results use SARIF's `logicalLocations` rather than
`physicalLocation` -- there's no file/line for an OT asset to point at.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

_LEVEL_MAP = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _rule_descriptor(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation},
    }


def to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    # One rule descriptor per distinct rule_id, in first-seen order.
    rules_by_id: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = _rule_descriptor(f)
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _LEVEL_MAP[f.severity],
                "message": {"text": f.description},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": f.subject_id,
                                "kind": f.subject_kind,
                            }
                        ]
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ics-risk-radar",
                        "version": tool_version,
                        "informationUri": "https://github.com/codeinedark77",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(
    findings: list[Finding], path: str | Path, tool_version: str = "0.1.0"
) -> None:
    with open(path, "w") as fh:
        json.dump(to_sarif(findings, tool_version=tool_version), fh, indent=2)
