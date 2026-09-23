from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    PORT = "PORT"
    URL = "URL"
    JS_FILE = "JS_FILE"
    TECHNOLOGY = "TECHNOLOGY"


@dataclass
class Asset:
    type: AssetType
    value: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "first_seen": self.first_seen,
        }


@dataclass
class Relationship:
    from_asset_id: str
    to_asset_id: str
    relation_type: str
    source: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "from_asset_id": self.from_asset_id,
            "to_asset_id": self.to_asset_id,
            "relation_type": self.relation_type,
            "source": self.source,
            "timestamp": self.timestamp,
        }


class AssetRegistry:
    def __init__(self):
        self._assets: dict[tuple[str, str], Asset] = {}
        self._relationships: list[Relationship] = []

    def get_or_create(self, asset_type: AssetType, value: str) -> Asset:
        key = (asset_type.value, value)
        if key not in self._assets:
            self._assets[key] = Asset(type=asset_type, value=value)
        return self._assets[key]

    def link(self, from_asset: Asset, to_asset: Asset, relation_type: str, source: str) -> None:
        self._relationships.append(
            Relationship(
                from_asset_id=from_asset.id,
                to_asset_id=to_asset.id,
                relation_type=relation_type,
                source=source,
            )
        )

    def all_assets(self) -> list[Asset]:
        return list(self._assets.values())

    def all_relationships(self) -> list[Relationship]:
        return list(self._relationships)