"""Closed connector dispatch over injected ports only."""

from __future__ import annotations

from ..contracts import ConnectorKind, ReadPlan
from .base import ConnectorFailure, ConnectorPage, ConnectorPort
from .event import EventBinding, read_event
from .file import FileBinding, read_file
from .http import HttpBinding, read_http
from .postgresql import PostgresBinding, read_postgresql

Binding = FileBinding | HttpBinding | PostgresBinding | EventBinding


def binding_digest(binding: Binding) -> str:
    return binding.binding_digest


def execute(
    plan: ReadPlan,
    binding: Binding,
    port: ConnectorPort,
    *,
    parameters: object | None = None,
    checkpoint: str | None = None,
) -> tuple[ConnectorPage, ...]:
    expected = {
        ConnectorKind.FILE: FileBinding,
        ConnectorKind.HTTP: HttpBinding,
        ConnectorKind.POSTGRESQL: PostgresBinding,
        ConnectorKind.EVENT: EventBinding,
    }[plan.connector_kind]
    if not isinstance(binding, expected):
        raise ConnectorFailure("CONNECTOR_BINDING_KIND_MISMATCH")
    if plan.connector_kind is ConnectorKind.FILE:
        return read_file(plan, binding, port)  # type: ignore[arg-type]
    if plan.connector_kind is ConnectorKind.HTTP:
        return read_http(plan, binding, port)  # type: ignore[arg-type]
    if plan.connector_kind is ConnectorKind.POSTGRESQL:
        return read_postgresql(plan, binding, port, parameters)  # type: ignore[arg-type]
    return read_event(plan, binding, port, checkpoint)  # type: ignore[arg-type]


__all__ = [
    "Binding",
    "ConnectorFailure",
    "ConnectorPage",
    "ConnectorPort",
    "EventBinding",
    "FileBinding",
    "HttpBinding",
    "PostgresBinding",
    "binding_digest",
    "execute",
]
