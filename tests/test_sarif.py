import json

from ics_risk_radar.models import Finding, Severity
from ics_risk_radar.sarif import to_sarif, write_sarif


def make_finding(
    rule_id="ICS-001",
    severity=Severity.CRITICAL,
    subject_id="a1",
    subject_kind="asset",
):
    return Finding(
        subject_id=subject_id,
        subject_kind=subject_kind,
        rule_id=rule_id,
        title="Test finding",
        description="A test finding description.",
        severity=severity,
        recommendation="Do the thing.",
    )


def test_sarif_top_level_shape():
    doc = to_sarif([make_finding()])
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "ics-risk-radar"


def test_sarif_result_count_matches_findings():
    findings = [make_finding(subject_id="a1"), make_finding(subject_id="a2")]
    doc = to_sarif(findings)
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_rules_deduplicated_by_rule_id():
    findings = [
        make_finding(rule_id="ICS-001"),
        make_finding(rule_id="ICS-001"),
    ]
    doc = to_sarif(findings)
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_sarif_severity_level_mapping():
    critical = to_sarif([make_finding(severity=Severity.CRITICAL)])
    low = to_sarif([make_finding(severity=Severity.LOW)])
    medium = to_sarif([make_finding(severity=Severity.MEDIUM)])
    assert critical["runs"][0]["results"][0]["level"] == "error"
    assert low["runs"][0]["results"][0]["level"] == "note"
    assert medium["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_logical_location_carries_subject():
    doc = to_sarif([make_finding(subject_id="plc-9", subject_kind="asset")])
    loc = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert loc["fullyQualifiedName"] == "plc-9"
    assert loc["kind"] == "asset"


def test_sarif_is_json_serializable():
    doc = to_sarif([make_finding()])
    json.loads(json.dumps(doc))  # must not raise


def test_write_sarif_to_file(tmp_path):
    out = tmp_path / "findings.sarif"
    write_sarif([make_finding()], out)
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_empty_findings_produces_valid_empty_sarif():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
