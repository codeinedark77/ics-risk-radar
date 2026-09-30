import pytest
from pydantic import ValidationError

from ics_risk_radar.models import (
    Asset,
    AssetCriticality,
    AssetType,
    Conduit,
    Finding,
    Protocol,
    Severity,
    Zone,
)


def test_zone_defaults():
    z = Zone(id="z1", name="Level 1 Control")
    assert z.criticality == AssetCriticality.MEDIUM
    assert z.description == ""


def test_zone_blank_id_rejected():
    with pytest.raises(ValidationError):
        Zone(id="   ", name="bad")


def test_asset_minimal_construction():
    a = Asset(id="a1", name="PLC-1", asset_type=AssetType.PLC, zone_id="z1")
    assert a.criticality == AssetCriticality.MEDIUM
    assert a.has_authentication is True
    assert a.uses_default_credentials is False
    assert a.protocols == []


def test_asset_blank_id_rejected():
    with pytest.raises(ValidationError):
        Asset(id="", name="x", asset_type=AssetType.PLC, zone_id="z1")


def test_conduit_construction():
    c = Conduit(
        id="c1",
        source_zone="it",
        target_zone="ot",
        protocols=[Protocol.MODBUS_TCP],
    )
    assert c.has_firewall is False
    assert c.is_monitored is False
    assert Protocol.MODBUS_TCP in c.protocols


def test_finding_autogenerates_id_and_timestamp():
    f1 = Finding(
        subject_id="a1",
        subject_kind="asset",
        rule_id="ICS-001",
        title="t",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
    )
    f2 = Finding(
        subject_id="a1",
        subject_kind="asset",
        rule_id="ICS-001",
        title="t",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
    )
    assert f1.id != f2.id
    assert f1.created_at is not None


def test_severity_ordering_is_string_enum():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO == "info"
