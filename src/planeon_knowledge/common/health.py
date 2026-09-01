"""Fail-closed dependency health aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping

from .validation import token, utc_seconds


class HealthState(StrEnum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    NOT_READY = "NOT_READY"


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    name: str
    state: HealthState
    checked_at: str
    reason_code: str

    def __post_init__(self) -> None:
        token(self.name, "dependency name")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.checked_at, "checkedAt")

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "state": self.state.value,
            "checkedAt": self.checked_at,
            "reasonCode": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class Readiness:
    state: HealthState
    dependencies: tuple[DependencyHealth, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": "planeon.knowledge.health/v1",
            "state": self.state.value,
            "dependencies": [item.as_dict() for item in self.dependencies],
        }


Probe = Callable[[], DependencyHealth]
REQUIRED = ("identity-admission", "policy", "contract-mock", "owned-store")
OPTIONAL = ("telemetry",)


def evaluate_readiness(probes: Mapping[str, Probe]) -> Readiness:
    if set(probes) != set(REQUIRED + OPTIONAL):
        return Readiness(HealthState.NOT_READY, ())
    results: list[DependencyHealth] = []
    for name in REQUIRED + OPTIONAL:
        try:
            result = probes[name]()
            if result.name != name:
                raise ValueError("probe name mismatch")
        except Exception:
            return Readiness(HealthState.NOT_READY, tuple(results))
        results.append(result)
    if any(item.state is not HealthState.READY for item in results if item.name in REQUIRED):
        state = HealthState.NOT_READY
    elif any(item.state is not HealthState.READY for item in results if item.name in OPTIONAL):
        state = HealthState.DEGRADED
    else:
        state = HealthState.READY
    return Readiness(state, tuple(results))
