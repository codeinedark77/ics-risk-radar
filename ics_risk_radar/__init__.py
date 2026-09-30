"""ics-risk-radar: defensive risk assessment for OT/ICS environments.

Public API surface. Everything here is assessment/scoring logic over
user-supplied asset metadata and numeric telemetry -- there is no
protocol client code and no code that talks to real field devices.
"""

from .compliance import compliance_summary, map_finding
from .inventory import AssetInventory, DuplicateIdError, UnknownZoneError
from .models import (
    Asset,
    AssetCriticality,
    AssetType,
    Conduit,
    Finding,
    Protocol,
    RiskScore,
    Severity,
    Zone,
)
from .report import build_report, write_report
from .risk_engine import RiskEngine
from .sarif import to_sarif, write_sarif
from .topology import evaluate_topology

__version__ = "0.2.0"

__all__ = [
    "Asset",
    "AssetCriticality",
    "AssetInventory",
    "AssetType",
    "Conduit",
    "DuplicateIdError",
    "Finding",
    "Protocol",
    "RiskEngine",
    "RiskScore",
    "Severity",
    "UnknownZoneError",
    "Zone",
    "build_report",
    "compliance_summary",
    "evaluate_topology",
    "map_finding",
    "to_sarif",
    "write_report",
    "write_sarif",
    "__version__",
]
