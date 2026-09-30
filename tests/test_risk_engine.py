from datetime import datetime, timezone

import pytest

from ics_risk_radar.inventory import AssetInventory
from ics_risk_radar.models import Asset, AssetType, Conduit, Zone
from ics_risk_radar.risk_engine import RiskEngine


@pytest.fixture
def inv():
    i = AssetInventory()
    i.add_zone(Zone(id="ot", name="OT"))
    i.add_zone(Zone(id="it", name="IT"))
    return i


def test_clean_asset_scores_zero(inv):
    # last_patched must be set explicitly, or ICS-006 (no patch date on
    # record) fires and this is no longer a zero-finding asset.
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="ot",
            last_patched=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    engine = RiskEngine(inv)
    scores = engine.score_assets()
    assert scores["a1"].score == 0.0
    assert scores["a1"].severity_band.value == "info"


def test_risky_asset_scores_high(inv):
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="ot",
            internet_facing=True,
            uses_default_credentials=True,
            last_patched=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    engine = RiskEngine(inv)
    scores = engine.score_assets()
    assert scores["a1"].score > 60
    assert scores["a1"].severity_band.value in ("high", "critical")
    assert len(scores["a1"].finding_ids) == 2


def test_score_monotonic_with_more_findings(inv):
    inv.add_asset(
        Asset(
            id="light",
            name="L",
            asset_type=AssetType.PLC,
            zone_id="ot",
            has_authentication=False,
        )
    )
    inv.add_asset(
        Asset(
            id="heavy",
            name="H",
            asset_type=AssetType.PLC,
            zone_id="ot",
            has_authentication=False,
            internet_facing=True,
            uses_default_credentials=True,
        )
    )
    engine = RiskEngine(inv)
    scores = engine.score_assets()
    assert scores["heavy"].score > scores["light"].score


def test_score_never_exceeds_100(inv):
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="ot",
            internet_facing=True,
            uses_default_credentials=True,
            has_authentication=False,
            firmware_version="1.0",
            firmware_latest_known="9.9",
        )
    )
    engine = RiskEngine(inv)
    scores = engine.score_assets()
    assert scores["a1"].score <= 100.0


def test_zone_score_is_weakest_link(inv):
    inv.add_asset(
        Asset(id="safe", name="S", asset_type=AssetType.PLC, zone_id="ot")
    )
    inv.add_asset(
        Asset(
            id="risky",
            name="R",
            asset_type=AssetType.PLC,
            zone_id="ot",
            internet_facing=True,
        )
    )
    engine = RiskEngine(inv)
    zone_score = engine.score_zone("ot")
    assert zone_score == engine.score_assets()["risky"].score


def test_zone_score_empty_zone_is_zero(inv):
    engine = RiskEngine(inv)
    assert engine.score_zone("it") == 0.0


def test_zone_score_unknown_zone_raises(inv):
    engine = RiskEngine(inv)
    with pytest.raises(KeyError):
        engine.score_zone("does-not-exist")


def test_conduit_scoring(inv):
    inv.add_conduit(Conduit(id="c1", source_zone="it", target_zone="ot"))
    engine = RiskEngine(inv)
    scores = engine.score_conduits()
    assert scores["c1"].score > 0
    assert len(scores["c1"].finding_ids) == 2  # unmonitored + no firewall


def test_findings_aggregates_assets_and_conduits(inv):
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.PLC,
            zone_id="ot",
            internet_facing=True,
        )
    )
    inv.add_conduit(Conduit(id="c1", source_zone="it", target_zone="ot"))
    engine = RiskEngine(inv)
    all_findings = engine.findings()
    kinds = {f.subject_kind for f in all_findings}
    assert kinds == {"asset", "conduit"}


def test_topology_findings_included_in_findings_and_asset_score(inv):
    from ics_risk_radar.models import AssetCriticality

    # ot zone defaults to MEDIUM; a SAFETY-tier asset in it should trip ICS-201
    inv.add_asset(
        Asset(
            id="a1",
            name="A",
            asset_type=AssetType.SIS,
            zone_id="ot",
            criticality=AssetCriticality.SAFETY,
        )
    )
    engine = RiskEngine(inv)
    rule_ids = {f.rule_id for f in engine.findings()}
    assert "ICS-201" in rule_ids

    scores = engine.score_assets()
    assert scores["a1"].score > 0
