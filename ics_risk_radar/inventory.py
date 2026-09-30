"""In-memory asset/zone/conduit inventory with YAML load support."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from .models import Asset, Conduit, Zone


class DuplicateIdError(ValueError):
    pass


class UnknownZoneError(ValueError):
    pass


class AssetInventory:
    """Holds the set of zones, conduits, and assets under assessment."""

    def __init__(self) -> None:
        self._zones: dict[str, Zone] = {}
        self._conduits: dict[str, Conduit] = {}
        self._assets: dict[str, Asset] = {}

    # -- zones ----------------------------------------------------------
    def add_zone(self, zone: Zone) -> None:
        if zone.id in self._zones:
            raise DuplicateIdError(f"Zone id already registered: {zone.id}")
        self._zones[zone.id] = zone

    def get_zone(self, zone_id: str) -> Zone:
        return self._zones[zone_id]

    def zones(self) -> Iterable[Zone]:
        return list(self._zones.values())

    def has_zone(self, zone_id: str) -> bool:
        return zone_id in self._zones

    # -- conduits ---------------------------------------------------------
    def add_conduit(self, conduit: Conduit) -> None:
        if conduit.id in self._conduits:
            raise DuplicateIdError(
                f"Conduit id already registered: {conduit.id}"
            )
        for zid in (conduit.source_zone, conduit.target_zone):
            if zid not in self._zones:
                raise UnknownZoneError(
                    f"Conduit {conduit.id} references unknown zone {zid}"
                )
        self._conduits[conduit.id] = conduit

    def conduits(self) -> Iterable[Conduit]:
        return list(self._conduits.values())

    # -- assets ---------------------------------------------------------
    def add_asset(self, asset: Asset) -> None:
        if asset.id in self._assets:
            raise DuplicateIdError(f"Asset id already registered: {asset.id}")
        if asset.zone_id not in self._zones:
            raise UnknownZoneError(
                f"Asset {asset.id} references unknown zone {asset.zone_id}"
            )
        self._assets[asset.id] = asset

    def get_asset(self, asset_id: str) -> Asset:
        return self._assets[asset_id]

    def assets(self) -> Iterable[Asset]:
        return list(self._assets.values())

    def assets_in_zone(self, zone_id: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.zone_id == zone_id]

    # -- bulk load --------------------------------------------------------
    @classmethod
    def from_yaml(cls, path: str | Path) -> "AssetInventory":
        data = yaml.safe_load(Path(path).read_text()) or {}
        inv = cls()
        for z in data.get("zones", []) or []:
            inv.add_zone(Zone(**z))
        for c in data.get("conduits", []) or []:
            inv.add_conduit(Conduit(**c))
        for a in data.get("assets", []) or []:
            inv.add_asset(Asset(**a))
        return inv
