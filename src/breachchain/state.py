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

    def meets(self, requirement: str, target_name: str) -> bool:
        """Check one requires-predicate (see state_rules.py's vocabulary)
        against the current state. Unknown predicate strings fail closed
        (treated as unmet) rather than silently passing.
        """
        if requirement == "credential":
            return len(self.credentials) > 0
        if requirement.startswith("access:"):
            level = requirement.split(":", 1)[1]
            return any(a.asset == target_name and a.level == level for a in self.access)
        return False

    def eligible(self, requires: list[str], target_name: str) -> bool:
        return all(self.meets(r, target_name) for r in requires)

    def apply_provides(self, provides: list[str], stdout: str, target_name: str, technique_id: str) -> None:
        """Apply a candidate's provides-effects after a successful run.
        Currently only "credential" is implemented (extracts from stdout via
        state_rules.extract_credentials); unknown effect strings are ignored.
        """
        if "credential" in provides:
            if __package__ in (None, ""):
                from breachchain.state_rules import extract_credentials
            else:
                from .state_rules import extract_credentials
            for identity in extract_credentials(stdout):
                self.add_credential(identity, source_asset=target_name, discovered_via=technique_id)
        for effect in provides:
            if effect.startswith("access:"):
                level = effect.split(":", 1)[1]
                self.add_access(target_name, level, technique_id)

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
