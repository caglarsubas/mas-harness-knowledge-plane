"""Grant-bound file read planning with no filesystem access."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest

from ..contracts import ReadPlan
from .base import ConnectorFailure, ConnectorPage, ConnectorPort, enforce_page, require_attestations


@dataclass(frozen=True, slots=True)
class FileBinding:
    relative_path: str
    mount_grant_digest: str
    material_digest: str
    regular_file: bool
    symlink_free: bool

    def __post_init__(self) -> None:
        digest(self.mount_grant_digest, "mountGrantDigest")
        digest(self.material_digest, "materialDigest")
        if type(self.regular_file) is not bool or type(self.symlink_free) is not bool:
            raise ValueError("file attestations must be boolean")
        if not isinstance(self.relative_path, str) or not 1 <= len(self.relative_path.encode("utf-8")) <= 512:
            raise ValueError("relative path is outside the closed range")
        if self.relative_path.startswith("/") or "\\" in self.relative_path or any(ord(character) < 32 for character in self.relative_path):
            raise ValueError("relative path is invalid")
        pieces = self.relative_path.split("/")
        candidate = PurePosixPath(self.relative_path)
        if any(piece in {"", ".", ".."} for piece in pieces) or candidate.is_absolute():
            raise ValueError("relative path traversal is forbidden")

    @property
    def binding_digest(self) -> str:
        return canonical_digest({
            "relativePath": self.relative_path,
            "mountGrantDigest": self.mount_grant_digest,
            "materialDigest": self.material_digest,
            "regularFile": self.regular_file,
            "symlinkFree": self.symlink_free,
        })


def read_file(plan: ReadPlan, binding: FileBinding, port: ConnectorPort) -> tuple[ConnectorPage, ...]:
    if binding.binding_digest != plan.binding_digest or not binding.regular_file or not binding.symlink_free:
        raise ConnectorFailure("FILE_BINDING_DENIED")
    page = port(plan, binding, None, None)
    enforce_page(plan, page)
    require_attestations(page, frozenset({"DEADLINE_BOUND", "MOUNT_GRANT_MATCH", "NO_SYMLINK", "READ_ONLY", "REGULAR_FILE"}))
    if page.next_token is not None or page.checkpoint_token is not None or page.payload_digest != binding.material_digest:
        raise ConnectorFailure("FILE_OBSERVATION_MISMATCH")
    return (page,)
