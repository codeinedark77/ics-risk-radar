from ics_risk_radar.compliance import compliance_summary, map_finding
from ics_risk_radar.models import Finding, Severity


def make_finding(rule_id):
    return Finding(
        subject_id="a1",
        subject_kind="asset",
        rule_id=rule_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
    )


def test_map_finding_known_rule():
    mapping = map_finding(make_finding("ICS-001"))
    assert ("IEC 62443-3-3", "SR 5.1 Network segmentation") in mapping
    assert any(fw == "NIST SP 800-82" for fw, _ in mapping)


def test_map_finding_unknown_rule_returns_empty():
    assert map_finding(make_finding("ICS-999")) == []


def test_compliance_summary_aggregates_across_findings():
    findings = [make_finding("ICS-001"), make_finding("ICS-102")]
    summary = compliance_summary(findings)
    assert "IEC 62443-3-3" in summary
    # both rules touch the same IEC 62443 segmentation control family
    assert "SR 5.1 Network segmentation" in summary["IEC 62443-3-3"]


def test_compliance_summary_empty_for_no_findings():
    assert compliance_summary([]) == {}
