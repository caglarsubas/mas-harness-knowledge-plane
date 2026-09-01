"""Prepared read-only PostgreSQL plan validation with an injected port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token

from ..contracts import ReadPlan
from .base import ConnectorFailure, ConnectorPage, ConnectorPort, enforce_page, require_attestations


def _parameters(value: object) -> dict[str, str | int | bool | None]:
    if not isinstance(value, dict) or len(value) > 32 or not all(isinstance(name, str) for name in value):
        raise ConnectorFailure("POSTGRES_PARAMETERS_INVALID")
    result: dict[str, str | int | bool | None] = {}
    for name, item in value.items():
        try:
            token(name, "parameter")
        except ValueError as exc:
            raise ConnectorFailure("POSTGRES_PARAMETERS_INVALID") from exc
        if item is not None and not isinstance(item, (str, int, bool)):
            raise ConnectorFailure("POSTGRES_PARAMETERS_INVALID")
        if isinstance(item, int) and not isinstance(item, bool) and not -(2**63) <= item <= 2**63 - 1:
            raise ConnectorFailure("POSTGRES_PARAMETERS_INVALID")
        if isinstance(item, str) and len(item.encode("utf-8")) > 1024:
            raise ConnectorFailure("POSTGRES_PARAMETERS_INVALID")
        result[name] = item
    return result


@dataclass(frozen=True, slots=True)
class PostgresBinding:
    statement_id: str
    statement_digest: str
    read_only: bool
    prepared: bool
    row_limit: int
    statement_timeout_ms: int

    def __post_init__(self) -> None:
        token(self.statement_id, "statementId")
        digest(self.statement_digest, "statementDigest")
        if self.read_only is not True or self.prepared is not True:
            raise ValueError("PostgreSQL binding must be read-only and prepared")
        if not isinstance(self.row_limit, int) or isinstance(self.row_limit, bool) or not 1 <= self.row_limit <= 10_000:
            raise ValueError("PostgreSQL row limit is invalid")
        if not isinstance(self.statement_timeout_ms, int) or isinstance(self.statement_timeout_ms, bool) or not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("PostgreSQL timeout is invalid")

    @property
    def binding_digest(self) -> str:
        return canonical_digest({
            "statementId": self.statement_id,
            "statementDigest": self.statement_digest,
            "readOnly": self.read_only,
            "prepared": self.prepared,
            "rowLimit": self.row_limit,
            "statementTimeoutMs": self.statement_timeout_ms,
        })


def read_postgresql(plan: ReadPlan, binding: PostgresBinding, port: ConnectorPort, parameters: object | None) -> tuple[ConnectorPage, ...]:
    if binding.binding_digest != plan.binding_digest or binding.row_limit > plan.max_records or binding.statement_timeout_ms > plan.deadline_ms:
        raise ConnectorFailure("POSTGRES_BINDING_DENIED")
    closed_parameters: dict[str, Any] = _parameters(parameters if parameters is not None else {})
    page = port(plan, binding, None, closed_parameters)
    enforce_page(plan, page)
    require_attestations(page, frozenset({"DEADLINE_BOUND", "PREPARED_EXECUTION", "READ_ONLY_TRANSACTION", "SERVER_LIMIT_BOUND", "STATEMENT_TIMEOUT_BOUND"}))
    if page.next_token is not None or page.checkpoint_token is not None:
        raise ConnectorFailure("POSTGRES_OBSERVATION_MISMATCH")
    return (page,)
