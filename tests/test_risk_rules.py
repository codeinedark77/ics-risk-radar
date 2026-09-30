from ics_risk_radar.models import Asset, AssetType, Conduit, Protocol
from ics_risk_radar.risk_rules import evaluate_asset, evaluate_conduit


def make_asset(**kwargs):
    base = dict(id="a1", name="A", asset_type=AssetType.PLC, zone_id="z1")
    base.update(kwargs)
    return Asset(**base)


def test_clean_asset_has_no_findings():
    from datetime import datetime, timezone

    a = make_asset(
        has_authentication=True,
        last_patched=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    findings = evaluate_asset(a)
    assert findings == []


def test_internet_facing_flagged_critical():
    a = make_asset(internet_facing=True)
    findings = evaluate_asset(a)
    rule_ids = {f.rule_id for f in findings}
    assert "ICS-001" in rule_ids
    f = next(f for f in findings if f.rule_id == "ICS-001")
    assert f.severity.value == "critical"


def test_default_credentials_flagged():
    a = make_asset(uses_default_credentials=True)
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-002" for f in findings)


def test_no_auth_flagged():
    a = make_asset(has_authentication=False)
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-003" for f in findings)


def test_stale_firmware_flagged():
    a = make_asset(firmware_version="1.2.0", firmware_latest_known="1.4.0")
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-004" for f in findings)


def test_matching_firmware_not_flagged():
    a = make_asset(firmware_version="1.4.0", firmware_latest_known="1.4.0")
    findings = evaluate_asset(a)
    assert not any(f.rule_id == "ICS-004" for f in findings)


def test_unauthenticated_protocol_flagged():
    a = make_asset(protocols=[Protocol.MODBUS_TCP])
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-005" for f in findings)


def test_opc_ua_not_flagged_for_ics005():
    a = make_asset(protocols=[Protocol.OPC_UA])
    findings = evaluate_asset(a)
    assert not any(f.rule_id == "ICS-005" for f in findings)


def test_multiple_findings_accumulate():
    a = make_asset(
        internet_facing=True,
        uses_default_credentials=True,
        has_authentication=False,
    )
    findings = evaluate_asset(a)
    rule_ids = {f.rule_id for f in findings}
    assert {"ICS-001", "ICS-002", "ICS-003"}.issubset(rule_ids)


def test_conduit_unmonitored_flagged():
    c = Conduit(
        id="c1", source_zone="it", target_zone="ot", is_monitored=False
    )
    findings = evaluate_conduit(c)
    assert any(f.rule_id == "ICS-101" for f in findings)


def test_conduit_no_firewall_flagged():
    c = Conduit(
        id="c1", source_zone="it", target_zone="ot", has_firewall=False
    )
    findings = evaluate_conduit(c)
    assert any(f.rule_id == "ICS-102" for f in findings)


def test_conduit_monitored_and_firewalled_is_clean():
    c = Conduit(
        id="c1",
        source_zone="it",
        target_zone="ot",
        is_monitored=True,
        has_firewall=True,
    )
    findings = evaluate_conduit(c)
    assert findings == []


def test_findings_reference_correct_subject():
    a = make_asset(id="plc-42", internet_facing=True)
    findings = evaluate_asset(a)
    assert all(
        f.subject_id == "plc-42" and f.subject_kind == "asset"
        for f in findings
    )


def test_no_patch_date_flagged():
    a = make_asset(last_patched=None)
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-006" for f in findings)


def test_patch_date_present_not_flagged():
    from datetime import datetime, timezone

    a = make_asset(last_patched=datetime(2026, 1, 1, tzinfo=timezone.utc))
    findings = evaluate_asset(a)
    assert not any(f.rule_id == "ICS-006" for f in findings)


def test_proprietary_protocol_flagged():
    a = make_asset(protocols=[Protocol.PROPRIETARY])
    findings = evaluate_asset(a)
    assert any(f.rule_id == "ICS-007" for f in findings)


def test_non_proprietary_protocol_not_flagged_for_ics007():
    a = make_asset(protocols=[Protocol.OPC_UA])
    findings = evaluate_asset(a)
    assert not any(f.rule_id == "ICS-007" for f in findings)
