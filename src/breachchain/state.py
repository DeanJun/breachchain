"""Simplified state accumulation: assets, credentials, and access gained
across a scenario run. Backed by a plain JSON dict per Section 8's decision
to skip a formal graph structure for the minimum viable scope.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Asset:
    name: str
    kind: str  # "node" | "file" | "service"
    discovered_via: str  # technique_id that revealed this asset


@dataclass
class Credential:
    identity: str
    source_asset: str
    discovered_via: str  # technique_id


@dataclass
class AccessGrant:
    asset: str
    level: str  # "user" | "root" | "read" | ...
    discovered_via: str


@dataclass
class ScenarioState:
    assets: list[Asset] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    access: list[AccessGrant] = field(default_factory=list)
    history: list[str] = field(default_factory=list)  # technique_ids in execution order

    def add_asset(self, name: str, kind: str, discovered_via: str) -> None:
        if not any(a.name == name for a in self.assets):
            self.assets.append(Asset(name, kind, discovered_via))

    def add_credential(self, identity: str, source_asset: str, discovered_via: str) -> None:
        if not any(c.identity == identity for c in self.credentials):
            self.credentials.append(Credential(identity, source_asset, discovered_via))

    def add_access(self, asset: str, level: str, discovered_via: str) -> None:
        if not any(a.asset == asset and a.level == level for a in self.access):
            self.access.append(AccessGrant(asset, level, discovered_via))

    def record_step(self, technique_id: str) -> None:
        self.history.append(technique_id)

    def to_dict(self) -> dict:
        return {
            "assets": [asdict(a) for a in self.assets],
            "credentials": [asdict(c) for c in self.credentials],
            "access": [asdict(a) for a in self.access],
            "history": self.history,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "ScenarioState":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            assets=[Asset(**a) for a in raw.get("assets", [])],
            credentials=[Credential(**c) for c in raw.get("credentials", [])],
            access=[AccessGrant(**a) for a in raw.get("access", [])],
            history=raw.get("history", []),
        )
