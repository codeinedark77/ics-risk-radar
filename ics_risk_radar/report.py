"""Report generation: JSON summary report for an inventory assessment."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .anomaly import RollingZScoreDetector
from .compliance import compliance_summary
from .inventory import AssetInventory
from .risk_engine import RiskEngine


def build_report(
    inventory: AssetInventory,
    telemetry: dict[str, list[float]] | None = None,
    anomaly_window: int = 20,
    anomaly_threshold: float = 3.0,
) -> dict:
    """`telemetry`, if given, maps asset_id -> a numeric time series for
    that asset (packet rate, cycle time, whatever you're tracking).
    Optional and additive -- omitting it reproduces the exact report
    shape from before telemetry support existed, so this is backward
    compatible with existing callers."""
    engine = RiskEngine(inventory)
    findings = engine.findings()
    asset_scores = engine.score_assets()
    conduit_scores = engine.score_conduits()
    zone_scores = {z.id: engine.score_zone(z.id) for z in inventory.zones()}

    anomalies: dict[str, list[dict]] = {}
    if telemetry:
        detector = RollingZScoreDetector(
            window=anomaly_window, threshold=anomaly_threshold
        )
        for asset_id, series in telemetry.items():
            points = detector.detect(series)
            if points:
                anomalies[asset_id] = [
                    {"index": p.index, "value": p.value, "z_score": p.z_score}
                    for p in points
                ]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "assets": len(list(inventory.assets())),
            "zones": len(list(inventory.zones())),
            "conduits": len(list(inventory.conduits())),
            "findings": len(findings),
            "assets_with_anomalies": len(anomalies),
        },
        "zone_scores": zone_scores,
        "asset_scores": {
            k: v.model_dump(mode="json") for k, v in asset_scores.items()
        },
        "conduit_scores": {
            k: v.model_dump(mode="json") for k, v in conduit_scores.items()
        },
        "findings": [f.model_dump(mode="json") for f in findings],
        "compliance_touchpoints": {
            k: sorted(v) for k, v in compliance_summary(findings).items()
        },
    }
    if telemetry:
        report["anomalies"] = anomalies
    return report


def write_report(
    inventory: AssetInventory, path: str, **build_report_kwargs
) -> None:
    report = build_report(inventory, **build_report_kwargs)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
