"""Tenant-isolated connector declaration and immutable staging boundary."""

from .service import IngestionFailure, IngestionService
from .store import InMemoryIngestionStore

__all__ = ["InMemoryIngestionStore", "IngestionFailure", "IngestionService"]
