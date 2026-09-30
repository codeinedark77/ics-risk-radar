from ics_risk_radar.inventory import AssetInventory
from ics_risk_radar.models import Asset, AssetCriticality, AssetType, Zone
from ics_risk_radar.topology import evaluate_topology


def test_asset_matching_zone_criticality_not_flagged():
    inv = AssetInventory()
    inv.add_zone(Zone(id="z1", name="Z1", criticality=AssetCriticality.HIGH))
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="z1",
            criticality=AssetCriticality.HIGH,
        )
    )
    findings = evaluate_topology(inv)
    assert findings == []


def test_asset_below_zone_criticality_not_flagged():
    inv = AssetInventory()
    inv.add_zone(Zone(id="z1", name="Z1", criticality=AssetCriticality.SAFETY))
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="z1",
            criticality=AssetCriticality.LOW,
        )
    )
    findings = evaluate_topology(inv)
    assert findings == []


def test_asset_exceeding_zone_criticality_flagged():
    inv = AssetInventory()
    inv.add_zone(Zone(id="z1", name="Z1", criticality=AssetCriticality.LOW))
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.SIS,
            zone_id="z1",
            criticality=AssetCriticality.SAFETY,
        )
    )
    findings = evaluate_topology(inv)
    assert len(findings) == 1
    assert findings[0].rule_id == "ICS-201"
    assert findings[0].subject_id == "a1"
    assert findings[0].severity.value == "high"


def test_multiple_mismatches_all_flagged():
    inv = AssetInventory()
    inv.add_zone(Zone(id="z1", name="Z1", criticality=AssetCriticality.LOW))
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="z1",
            criticality=AssetCriticality.HIGH,
        )
    )
    inv.add_asset(
        Asset(
            id="a2",
            name="B",
            asset_type=AssetType.PLC,
            zone_id="z1",
            criticality=AssetCriticality.MEDIUM,
        )
    )
    findings = evaluate_topology(inv)
    assert {f.subject_id for f in findings} == {"a1", "a2"}
