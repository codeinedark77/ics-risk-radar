import pytest

from ics_risk_radar.inventory import (
    AssetInventory,
    DuplicateIdError,
    UnknownZoneError,
)
from ics_risk_radar.models import Asset, AssetType, Conduit, Zone


def make_zone(zid="z1"):
    return Zone(id=zid, name=f"Zone {zid}")


def make_asset(aid="a1", zone_id="z1"):
    return Asset(
        id=aid, name=f"Asset {aid}", asset_type=AssetType.PLC, zone_id=zone_id
    )


def test_add_and_get_zone():
    inv = AssetInventory()
    inv.add_zone(make_zone("z1"))
    assert inv.get_zone("z1").id == "z1"
    assert list(inv.zones())[0].id == "z1"


def test_duplicate_zone_rejected():
    inv = AssetInventory()
    inv.add_zone(make_zone("z1"))
    with pytest.raises(DuplicateIdError):
        inv.add_zone(make_zone("z1"))


def test_asset_requires_known_zone():
    inv = AssetInventory()
    with pytest.raises(UnknownZoneError):
        inv.add_asset(make_asset("a1", zone_id="missing"))


def test_duplicate_asset_rejected():
    inv = AssetInventory()
    inv.add_zone(make_zone("z1"))
    inv.add_asset(make_asset("a1"))
    with pytest.raises(DuplicateIdError):
        inv.add_asset(make_asset("a1"))


def test_conduit_requires_known_zones():
    inv = AssetInventory()
    inv.add_zone(make_zone("it"))
    with pytest.raises(UnknownZoneError):
        inv.add_conduit(Conduit(id="c1", source_zone="it", target_zone="ot"))


def test_assets_in_zone():
    inv = AssetInventory()
    inv.add_zone(make_zone("z1"))
    inv.add_zone(make_zone("z2"))
    inv.add_asset(make_asset("a1", "z1"))
    inv.add_asset(make_asset("a2", "z1"))
    inv.add_asset(make_asset("a3", "z2"))
    assert {a.id for a in inv.assets_in_zone("z1")} == {"a1", "a2"}
    assert {a.id for a in inv.assets_in_zone("z2")} == {"a3"}


def test_from_yaml(tmp_path):
    yaml_content = """
zones:
  - id: it
    name: IT Network
  - id: ot
    name: OT Network
    criticality: high
conduits:
  - id: it-ot
    source_zone: it
    target_zone: ot
    protocols: [modbus_tcp]
assets:
  - id: plc-1
    name: Main PLC
    asset_type: plc
    zone_id: ot
    internet_facing: true
"""
    p = tmp_path / "inv.yaml"
    p.write_text(yaml_content)
    inv = AssetInventory.from_yaml(p)
    assert inv.get_zone("ot").criticality.value == "high"
    assert inv.get_asset("plc-1").internet_facing is True
    assert list(inv.conduits())[0].id == "it-ot"


def test_from_yaml_empty_file(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    inv = AssetInventory.from_yaml(p)
    assert list(inv.zones()) == []
    assert list(inv.assets()) == []
