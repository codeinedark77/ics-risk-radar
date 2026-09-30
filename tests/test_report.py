import json

from ics_risk_radar.inventory import AssetInventory
from ics_risk_radar.models import Asset, AssetType, Zone
from ics_risk_radar.report import build_report, write_report


def build_sample_inventory():
    inv = AssetInventory()
    inv.add_zone(Zone(id="ot", name="OT"))
    inv.add_asset(
        Asset(
            id="a1",
            name="PLC-1",
            asset_type=AssetType.PLC,
            zone_id="ot",
            internet_facing=True,
        )
    )
    return inv


def test_build_report_structure():
    report = build_report(build_sample_inventory())
    assert report["summary"]["assets"] == 1
    assert report["summary"]["zones"] == 1
    assert report["summary"]["findings"] >= 1
    assert "ot" in report["zone_scores"]
    assert "a1" in report["asset_scores"]
    assert isinstance(report["findings"], list)
    assert "compliance_touchpoints" in report


def test_report_is_json_serializable():
    report = build_report(build_sample_inventory())
    text = json.dumps(report, default=str)
    reparsed = json.loads(text)
    assert reparsed["summary"]["assets"] == 1


def test_write_report_to_file(tmp_path):
    out = tmp_path / "report.json"
    write_report(build_sample_inventory(), str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["summary"]["assets"] == 1


def test_report_without_telemetry_has_no_anomalies_key():
    report = build_report(build_sample_inventory())
    assert "anomalies" not in report
    assert report["summary"]["assets_with_anomalies"] == 0


def test_report_with_telemetry_flat_series_no_anomalies():
    telemetry = {"a1": [10.0] * 30}
    report = build_report(build_sample_inventory(), telemetry=telemetry)
    assert report["anomalies"] == {}
    assert report["summary"]["assets_with_anomalies"] == 0


def test_report_with_telemetry_spike_detected():
    series = [10.0] * 30
    series[25] = 900.0
    telemetry = {"a1": series}
    report = build_report(build_sample_inventory(), telemetry=telemetry)
    assert "a1" in report["anomalies"]
    assert report["summary"]["assets_with_anomalies"] == 1
    assert report["anomalies"]["a1"][0]["index"] == 25


def test_report_is_json_serializable_with_telemetry():
    series = [10.0] * 25
    series[22] = 500.0
    report = build_report(build_sample_inventory(), telemetry={"a1": series})
    json.loads(json.dumps(report, default=str))
