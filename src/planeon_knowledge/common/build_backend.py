"""Inert build backend: KN-001 acceptance never builds or publishes."""

from __future__ import annotations


def _disabled(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("KN-001 source-only packet forbids artifact building")


build_wheel = _disabled
build_sdist = _disabled
build_editable = _disabled
