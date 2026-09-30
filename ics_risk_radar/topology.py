"""Cross-cutting (topology) risk checks that need the whole inventory,
not just a single asset or conduit -- e.g. whether an asset's declared
criticality is consistent with the zone it sits in. Kept separate from
risk_rules.py because these predicates need inventory context, not
just the one subject being evaluated.
"""

from __future__ import annotations

from .inventory import AssetInventory
from .models import AssetCriticality, Finding, Severity

_CRITICALITY_ORDER = {
    AssetCriticality.LOW: 0,
    AssetCriticality.MEDIUM: 1,
    AssetCriticality.HIGH: 2,
    AssetCriticality.SAFETY: 3,
}


def evaluate_topology(inventory: AssetInventory) -> list[Finding]:
    """Currently one check: an asset whose own criticality outranks the
    zone it's declared to live in. IEC 62443 zoning assumes everything
    in a zone shares that zone's security requirements -- an asset that
    outranks its zone is a sign the inventory itself is mis-zoned."""
    findings: list[Finding] = []
    for asset in inventory.assets():
        zone = inventory.get_zone(asset.zone_id)
        asset_rank = _CRITICALITY_ORDER[asset.criticality]
        zone_rank = _CRITICALITY_ORDER[zone.criticality]
        if asset_rank > zone_rank:
            findings.append(
                Finding(
                    subject_id=asset.id,
                    subject_kind="asset",
                    rule_id="ICS-201",
                    title="Asset criticality exceeds its zone's declared criticality",
                    description=(
                        f"Asset '{asset.id}' is criticality '{asset.criticality.value}' "
                        f"but sits in zone '{zone.id}', declared '{zone.criticality.value}'. "
                        "The zone's security requirements may not match what's actually "
                        "inside it."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Re-zone the asset to match its real criticality, or raise the "
                        "zone's declared criticality and re-check every conduit into it."
                    ),
                )
            )
    return findings
