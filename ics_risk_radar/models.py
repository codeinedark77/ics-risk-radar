"""Core data models for ICS Risk Radar.

Models follow IEC 62443 zone/conduit terminology for representing
Operational Technology (OT) / Industrial Control System (ICS) assets.
This module is pure data modeling -- no network or protocol code.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SAFETY = "safety"  # safety-instrumented system (SIS) tier


class AssetType(str, Enum):
    PLC = "plc"
    RTU = "rtu"
    HMI = "hmi"
    HISTORIAN = "historian"
    ENGINEERING_WORKSTATION = "engineering_workstation"
    NETWORK_SWITCH = "network_switch"
    FIREWALL = "firewall"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    SIS = "safety_instrumented_system"
    OTHER = "other"


class Protocol(str, Enum):
    MODBUS_TCP = "modbus_tcp"
    DNP3 = "dnp3"
    IEC_61850 = "iec_61850"
    BACNET = "bacnet"
    ETHERNET_IP = "ethernet_ip"
    OPC_UA = "opc_ua"
    PROPRIETARY = "proprietary"
    OTHER = "other"


class Zone(BaseModel):
    """An IEC 62443 security zone: assets that share security requirements."""

    id: str
    name: str
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    description: str = ""

    @field_validator("id")
    @classmethod
    def _id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Zone id cannot be blank")
        return v


class Conduit(BaseModel):
    """An IEC 62443 conduit: a communication path between two zones."""

    id: str
    source_zone: str
    target_zone: str
    protocols: list[Protocol] = Field(default_factory=list)
    has_unidirectional_gateway: bool = False
    has_firewall: bool = False
    is_monitored: bool = False


class Asset(BaseModel):
    """A single OT/ICS asset."""

    id: str
    name: str
    asset_type: AssetType
    zone_id: str
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    vendor: Optional[str] = None
    firmware_version: Optional[str] = None
    firmware_latest_known: Optional[str] = None
    protocols: list[Protocol] = Field(default_factory=list)
    internet_facing: bool = False
    has_authentication: bool = True
    uses_default_credentials: bool = False
    last_patched: Optional[datetime] = None

    @field_validator("id")
    @classmethod
    def _id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Asset id cannot be blank")
        return v


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A single risk finding tied to an asset or conduit."""

    id: UUID = Field(default_factory=uuid4)
    subject_id: str
    subject_kind: str  # "asset" | "conduit"
    rule_id: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class RiskScore(BaseModel):
    """Aggregated risk score for an asset or conduit, 0-100 (100 = highest risk)."""

    subject_id: str
    subject_kind: str
    score: float
    severity_band: Severity
    finding_ids: list[UUID] = Field(default_factory=list)
