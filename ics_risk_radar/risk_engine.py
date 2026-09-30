"""Aggregate rule findings into per-asset / per-conduit / per-zone risk scores."""

from __future__ import annotations

from .inventory import AssetInventory
from .models import Finding, RiskScore, Severity
from .risk_rules import evaluate_asset, evaluate_conduit
from .topology import evaluate_topology

_SEVERITY_WEIGHT = {
    Severity.INFO: 2,
    Severity.LOW: 8,
    Severity.MEDIUM: 20,
    Severity.HIGH: 35,
    Severity.CRITICAL: 55,
}

_BAND_THRESHOLDS = [
    (85.0, Severity.CRITICAL),
    (60.0, Severity.HIGH),
    (30.0, Severity.MEDIUM),
    (10.0, Severity.LOW),
    (0.0, Severity.INFO),
]


def _band_for(score: float) -> Severity:
    for threshold, band in _BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return Severity.INFO


def _score_from_findings(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    raw = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    # Diminishing returns: a pile of low-severity findings shouldn't
    # blow past 100 as fast as a couple of criticals do.
    score = 100 * (1 - pow(0.5, raw / 40))
    return round(min(score, 100.0), 1)


class RiskEngine:
    """Runs the rule catalogue against an inventory and scores results."""

    def __init__(self, inventory: AssetInventory) -> None:
        self.inventory = inventory

    def _topology_findings_by_asset(self) -> dict[str, list[Finding]]:
        by_asset: dict[str, list[Finding]] = {}
        for f in evaluate_topology(self.inventory):
            by_asset.setdefault(f.subject_id, []).append(f)
        return by_asset

    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for asset in self.inventory.assets():
            out.extend(evaluate_asset(asset))
        for conduit in self.inventory.conduits():
            out.extend(evaluate_conduit(conduit))
        out.extend(evaluate_topology(self.inventory))
        return out

    def score_assets(self) -> dict[str, RiskScore]:
        topology_by_asset = self._topology_findings_by_asset()
        scores: dict[str, RiskScore] = {}
        for asset in self.inventory.assets():
            f = evaluate_asset(asset) + topology_by_asset.get(asset.id, [])
            s = _score_from_findings(f)
            scores[asset.id] = RiskScore(
                subject_id=asset.id,
                subject_kind="asset",
                score=s,
                severity_band=_band_for(s),
                finding_ids=[x.id for x in f],
            )
        return scores

    def score_conduits(self) -> dict[str, RiskScore]:
        scores: dict[str, RiskScore] = {}
        for conduit in self.inventory.conduits():
            f = evaluate_conduit(conduit)
            s = _score_from_findings(f)
            scores[conduit.id] = RiskScore(
                subject_id=conduit.id,
                subject_kind="conduit",
                score=s,
                severity_band=_band_for(s),
                finding_ids=[x.id for x in f],
            )
        return scores

    def score_zone(self, zone_id: str) -> float:
        """A zone's score is the max of its assets' scores (weakest-link model)."""
        if not self.inventory.has_zone(zone_id):
            raise KeyError(zone_id)
        asset_scores = self.score_assets()
        zone_assets = self.inventory.assets_in_zone(zone_id)
        if not zone_assets:
            return 0.0
        return max(asset_scores[a.id].score for a in zone_assets)
