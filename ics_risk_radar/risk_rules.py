"""Risk rule catalogue.

Each rule encodes a *publicly documented category* of OT/ICS risk
(protocol lacking native authentication, absence of network
segmentation, default credentials, stale firmware, etc.) drawn from
widely published guidance (IEC 62443, NIST SP 800-82, CISA ICS
advisories). This module contains no exploit code, no protocol
attack payloads, and does not talk to real devices -- it only
encodes assessment logic over user-supplied metadata: given facts
about an asset or conduit, does a known risk pattern apply?
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Union

from .models import Asset, Conduit, Finding, Protocol, Severity

Subject = Union[Asset, Conduit]

_UNAUTHENTICATED_PROTOCOLS = {
    Protocol.MODBUS_TCP,
    Protocol.DNP3,
    Protocol.BACNET,
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    applies_to: str  # "asset" | "conduit"
    predicate: Callable[[Subject], bool]
    description: str
    recommendation: str

    def evaluate(self, subject: Subject) -> Finding | None:
        if not self.predicate(subject):
            return None
        return Finding(
            subject_id=subject.id,
            subject_kind=self.applies_to,
            rule_id=self.id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            recommendation=self.recommendation,
        )


ASSET_RULES: list[Rule] = [
    Rule(
        id="ICS-001",
        title="Internet-facing OT asset",
        severity=Severity.CRITICAL,
        applies_to="asset",
        predicate=lambda a: bool(getattr(a, "internet_facing", False)),
        description=(
            "Asset is reachable from the public internet. OT assets are "
            "generally not designed to withstand internet-scale scanning "
            "and exploitation attempts."
        ),
        recommendation=(
            "Remove direct internet exposure; place behind a "
            "unidirectional gateway or IT/OT DMZ per IEC 62443-3-3."
        ),
    ),
    Rule(
        id="ICS-002",
        title="Default vendor credentials in use",
        severity=Severity.CRITICAL,
        applies_to="asset",
        predicate=lambda a: bool(
            getattr(a, "uses_default_credentials", False)
        ),
        description="Asset is reported to still use vendor-default credentials.",
        recommendation="Rotate to unique, managed credentials immediately.",
    ),
    Rule(
        id="ICS-003",
        title="No authentication on management interface",
        severity=Severity.HIGH,
        applies_to="asset",
        predicate=lambda a: not getattr(a, "has_authentication", True),
        description="Asset's management interface reports no authentication.",
        recommendation="Enable authentication, or compensate with strict network ACLs and monitoring.",
    ),
    Rule(
        id="ICS-004",
        title="Firmware behind latest known vendor release",
        severity=Severity.MEDIUM,
        applies_to="asset",
        predicate=lambda a: (
            getattr(a, "firmware_version", None) is not None
            and getattr(a, "firmware_latest_known", None) is not None
            and getattr(a, "firmware_version")
            != getattr(a, "firmware_latest_known")
        ),
        description="Installed firmware differs from the latest known vendor release.",
        recommendation="Schedule a maintenance window to validate and apply the vendor patch.",
    ),
    Rule(
        id="ICS-005",
        title="Unauthenticated-by-design protocol in use",
        severity=Severity.MEDIUM,
        applies_to="asset",
        predicate=lambda a: any(
            p in _UNAUTHENTICATED_PROTOCOLS
            for p in getattr(a, "protocols", [])
        ),
        description=(
            "Asset communicates over a protocol with no native "
            "authentication (e.g. Modbus TCP, classic DNP3, BACnet). "
            "This is a documented protocol-design limitation, not a "
            "vendor defect."
        ),
        recommendation=(
            "Compensate at the network layer: segmentation, allow-listed "
            "conduits, and monitoring for unexpected function codes."
        ),
    ),
    Rule(
        id="ICS-006",
        title="No patch date on record",
        severity=Severity.LOW,
        applies_to="asset",
        predicate=lambda a: getattr(a, "last_patched", None) is None,
        description=(
            "Asset has no recorded patch date, so patch currency cannot "
            "be verified from inventory data alone."
        ),
        recommendation="Record the last patch/maintenance date as part of routine asset hygiene.",
    ),
    Rule(
        id="ICS-007",
        title="Proprietary/undocumented protocol in use",
        severity=Severity.MEDIUM,
        applies_to="asset",
        predicate=lambda a: Protocol.PROPRIETARY
        in getattr(a, "protocols", []),
        description=(
            "Asset uses a proprietary protocol not covered by standard "
            "OT monitoring tooling, reducing visibility into its traffic."
        ),
        recommendation=(
            "Document the protocol's spec internally, or place the asset "
            "behind a conduit where its traffic can at least be flow-monitored "
            "even if not deep-inspected."
        ),
    ),
]

CONDUIT_RULES: list[Rule] = [
    Rule(
        id="ICS-101",
        title="Unmonitored IT/OT conduit",
        severity=Severity.HIGH,
        applies_to="conduit",
        predicate=lambda c: not getattr(c, "is_monitored", False),
        description="Conduit between zones has no monitoring in place.",
        recommendation="Add flow/anomaly monitoring at the conduit boundary.",
    ),
    Rule(
        id="ICS-102",
        title="No firewall between zones",
        severity=Severity.HIGH,
        applies_to="conduit",
        predicate=lambda c: not getattr(c, "has_firewall", False),
        description="Conduit has no firewall enforcing IEC 62443 zone separation.",
        recommendation="Deploy a firewall or unidirectional gateway matched to the zones' criticality gap.",
    ),
]


def evaluate_asset(asset: Asset) -> list[Finding]:
    out = []
    for r in ASSET_RULES:
        f = r.evaluate(asset)
        if f is not None:
            out.append(f)
    return out


def evaluate_conduit(conduit: Conduit) -> list[Finding]:
    out = []
    for r in CONDUIT_RULES:
        f = r.evaluate(conduit)
        if f is not None:
            out.append(f)
    return out
