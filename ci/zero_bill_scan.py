#!/usr/bin/env python3
"""Closed KN-001 source and CI zero-bill admission."""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from pathlib import Path

SERVICES = ("domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker", "memory-service")
FORBIDDEN_WORKFLOW = ("ubuntu-latest", "macos-latest", "windows-latest", "upload-artifact", "download-artifact", "actions/cache", "docker://", "schedule:", "push:", "packages: write")
FORBIDDEN_KINDS = ("kind: Secret", "kind: Namespace", "kind: PersistentVolume", "kind: PersistentVolumeClaim", "kind: Route", "kind: Ingress")
CONTENT_KEYS = {"apiKey", "authorization", "credential", "password", "secret", "token", "uri", "url", "filePath", "query", "payload", "prompt", "embedding", "modelOutput", "sourceContent"}


def refuse(message: str) -> None:
    raise SystemExit(f"zero-bill scan refused: {message}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            refuse(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def inspect_json(value: object, relative: str) -> None:
    if isinstance(value, dict):
        overlap = set(value) & CONTENT_KEYS
        if overlap:
            refuse(f"content-bearing field in {relative}: {sorted(overlap)[0]}")
        for item in value.values():
            inspect_json(item, relative)
    elif isinstance(value, list):
        for item in value:
            inspect_json(item, relative)


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
    if not root.is_dir() or root.is_symlink():
        refuse("scan root must be a regular directory")
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            if (Path(current) / name).is_symlink():
                refuse(f"linked source is forbidden: {(Path(current) / name).relative_to(root)}")
    workflow = (root / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    if any(token in workflow for token in FORBIDDEN_WORKFLOW):
        refuse("workflow contains a hosted, retained, scheduled, package, or container feature")
    required_workflow = (
        "pull_request:", "workflow_dispatch:", "permissions:\n  contents: read",
        "runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]",
        "timeout-minutes: 15", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "persist-credentials: false", "fetch-depth: 2", "run: /opt/planeon/bin/harness-offline-launch",
    )
    if any(token not in workflow for token in required_workflow) or workflow.count("uses:") != 1 or workflow.count("run:") != 1:
        refuse("workflow is outside the pinned two-step credential-free contract")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if project["project"].get("dependencies") != [] or project["build-system"].get("requires") != []:
        refuse("KN-001 dependency closure is not empty")
    for path in sorted((root / "contract-mocks").glob("*.json")):
        if path.name == "upstream-locks.json":
            continue
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        inspect_json(value, path.relative_to(root).as_posix())
    for service in SERVICES:
        container = (root / f"services/{service}/Containerfile").read_text(encoding="utf-8")
        if not re.search(r"(?m)^ARG BASE_IMAGE$", container) or "FROM ${BASE_IMAGE}" not in container:
            refuse(f"{service} does not require an externally supplied base digest")
        if re.search(r"(?m)^(RUN|ADD)\s", container) or "USER 65532:65532" not in container or "ENTRYPOINT [" not in container:
            refuse(f"{service} Containerfile can fetch, mutate, or run as root")
        chart = root / f"deploy/helm/{service}"
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        workload = (chart / "templates/workload.yaml").read_text(encoding="utf-8")
        network = (chart / "templates/networkpolicy.yaml").read_text(encoding="utf-8")
        if not values.startswith("enabled: false\n") or 'repository: ""' not in values or 'digest: ""' not in values or "enabled: true" in values:
            refuse(f"{service} chart defaults are not inert")
        required_chart = ("required \"image.repository is required\"", "required \"image.digest is required\"", "@{{ $digest }}", "runAsNonRoot: true", "readOnlyRootFilesystem: true", "allowPrivilegeEscalation: false", "drop: [\"ALL\"]", "type: RuntimeDefault", "automountServiceAccountToken: false", "resources:", "/health/live", "/health/ready")
        if any(token not in workload for token in required_chart) or any(token in workload for token in FORBIDDEN_KINDS):
            refuse(f"{service} chart security or provisioning contract drifted")
        if "policyTypes: [Ingress, Egress]" not in network or "ingress: []" not in network or "egress: []" not in network:
            refuse(f"{service} chart is not default deny")
    runtime_paths = [root / "src", root / "services", root / "deploy"]
    for base in runtime_paths:
        for path in base.rglob("*"):
            if path.is_file() and path.suffix not in {".pyc"}:
                text = path.read_text(encoding="utf-8")
                if "https://" in text or "http://" in text or "api_key" in text.casefold():
                    refuse(f"runtime source contains an external endpoint or API-key default: {path.relative_to(root)}")
    print("zero-bill scan passed: no hosted runner, retained Actions feature, paid/API-key dependency, mutable image, cloud provisioning, runtime download, public endpoint, or external telemetry default")


if __name__ == "__main__":
    main()
