import json

from ics_risk_radar.cli import main

SAMPLE_YAML = """
zones:
  - id: ot
    name: OT
assets:
  - id: a1
    name: PLC-1
    asset_type: plc
    zone_id: ot
    internet_facing: true
"""


def test_cli_scan_writes_file(tmp_path, capsys):
    inv_path = tmp_path / "inv.yaml"
    inv_path.write_text(SAMPLE_YAML)
    out_path = tmp_path / "report.json"

    rc = main(["scan", str(inv_path), "--out", str(out_path)])

    assert rc == 0
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["summary"]["assets"] == 1
    captured = capsys.readouterr()
    assert "Report written to" in captured.out


def test_cli_scan_prints_to_stdout(tmp_path, capsys):
    inv_path = tmp_path / "inv.yaml"
    inv_path.write_text(SAMPLE_YAML)

    rc = main(["scan", str(inv_path)])

    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["summary"]["assets"] == 1


def test_cli_requires_command():
    try:
        main([])
        assert False, "expected SystemExit for missing required subcommand"
    except SystemExit as e:
        assert e.code != 0


def test_cli_scan_with_telemetry(tmp_path):
    inv_path = tmp_path / "inv.yaml"
    inv_path.write_text(SAMPLE_YAML)
    telemetry_path = tmp_path / "telemetry.json"
    series = [10.0] * 30
    series[25] = 999.0
    telemetry_path.write_text(json.dumps({"a1": series}))
    out_path = tmp_path / "report.json"

    rc = main(
        [
            "scan",
            str(inv_path),
            "--telemetry",
            str(telemetry_path),
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    data = json.loads(out_path.read_text())
    assert "a1" in data["anomalies"]


def test_cli_scan_with_sarif_out(tmp_path, capsys):
    inv_path = tmp_path / "inv.yaml"
    inv_path.write_text(SAMPLE_YAML)
    sarif_path = tmp_path / "findings.sarif"

    rc = main(["scan", str(inv_path), "--sarif-out", str(sarif_path)])

    assert rc == 0
    assert sarif_path.exists()
    sarif_doc = json.loads(sarif_path.read_text())
    assert sarif_doc["version"] == "2.1.0"
    captured = capsys.readouterr()
    assert "SARIF written to" in captured.out
