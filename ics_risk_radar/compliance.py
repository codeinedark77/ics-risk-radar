"""Maps risk-rule IDs to reference control families.

This module holds mapping data only (which published control family a
finding relates to). It is a navigation aid, not a substitute for the
actual standards -- consult IEC 62443 / NIST SP 800-82 directly for
authoritative control language.
"""

from __future__ import annotations

from .models import Finding

# rule_id -> list of (framework, control_family)
_CONTROL_MAP: dict[str, list[tuple[str, str]]] = {
    "ICS-001": [
        ("IEC 62443-3-3", "SR 5.1 Network segmentation"),
        ("NIST SP 800-82", "SC-7 Boundary Protection"),
    ],
    "ICS-002": [
        ("IEC 62443-3-3", "SR 1.5 Authenticator management"),
        ("NIST SP 800-82", "IA-5 Authenticator Management"),
    ],
    "ICS-003": [
        ("IEC 62443-3-3", "SR 1.1 Human user identification & authentication"),
        ("NIST SP 800-82", "IA-2 Identification and Authentication"),
    ],
    "ICS-004": [
        ("IEC 62443-2-3", "Patch management"),
        ("NIST SP 800-82", "SI-2 Flaw Remediation"),
    ],
    "ICS-005": [
        ("IEC 62443-3-3", "SR 3.1 Communication integrity"),
        ("NIST SP 800-82", "SC-8 Transmission Confidentiality and Integrity"),
    ],
    "ICS-101": [
        ("IEC 62443-3-3", "SR 6.2 Continuous monitoring"),
        ("NIST SP 800-82", "SI-4 System Monitoring"),
    ],
    "ICS-102": [
        ("IEC 62443-3-3", "SR 5.1 Network segmentation"),
        ("NIST SP 800-82", "SC-7 Boundary Protection"),
    ],
    "ICS-006": [
        ("IEC 62443-2-3", "Patch management"),
        ("NIST SP 800-82", "CM-8 System Component Inventory"),
    ],
    "ICS-007": [
        ("IEC 62443-3-3", "SR 6.2 Continuous monitoring"),
        ("NIST SP 800-82", "SI-4 System Monitoring"),
    ],
    "ICS-201": [
        ("IEC 62443-3-2", "Zone and conduit partitioning"),
        ("NIST SP 800-82", "CA-3 System Interconnections"),
    ],
}


def map_finding(finding: Finding) -> list[tuple[str, str]]:
    return _CONTROL_MAP.get(finding.rule_id, [])


def compliance_summary(findings: list[Finding]) -> dict[str, set[str]]:
    """framework -> set of control families touched by these findings."""
    summary: dict[str, set[str]] = {}
    for f in findings:
        for framework, control in map_finding(f):
            summary.setdefault(framework, set()).add(control)
    return summary
