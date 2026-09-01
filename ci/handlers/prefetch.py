#!/usr/bin/env python3
"""Verify the already-present dependency-free KN-001 source closure."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "f3a3463d2fe04d4b17dc3abbebc6b3375bd6d890"
EXPECTED_LOCKS = {
    "base": {"commit": BASE, "repository": "mas-harness-knowledge-plane"},
    "contracts": {
        "commit": "2146278a95344cd2a8e22596b2f315b46edffc88",
        "entries": {
            "EvidenceRecord": "sha256:05ea50ee0ad9fb74414871c8c3fa572e9f1a22bbc667194f911834f26b829674",
            "LifecycleCloudEvent": "sha256:f0be09712101b61980e7752ae4a394bd09fa21640df4cbeeec4764f1e6004d0f",
            "LifecycleCommonTypes": "sha256:08326b0089973097698776011a2d5c386cd6e0e6490642f1b9bfd942d6f7e409",
            "PolicyBundle": "sha256:c0444183121d156d001d0b004975b14dd25df3a6065bd4ecfecd4c965a0fd13d",
            "TrustApi": "sha256:b16d5bd0a16186c4a6c98c5fce938f1b9e2c8fda562586f1466715de0b531271",
        },
        "raw": {
            "EvidenceRecord": "sha256:a80935c2dc5ac4624d972edc3876d301059c74e507ca2be28ea353b1070bdd8c",
            "LifecycleCloudEvent": "sha256:4e1282bda0b3f947265a84545ed5b2fdea0a1bb4e69af3642fc14c265811c56c",
            "LifecycleCommonTypes": "sha256:dce5d8030eea3a19694511eb26513614dcc720ef4e0d650772131b14ed58f075",
        },
        "releaseManifest": "sha256:c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79",
    },
    "met003": {
        "commit": "97da35afff79e1582b964b613472609a613ea81b",
        "policy": "sha256:77c1385d014db8562be215f03a806deafb66e38c6e7faed9167f53299dadd43e",
        "scanner": "sha256:57fa7e94bf5657f0daf959d5229dfc2a53a0ab94793d1d5fa03a7513b1272fd7",
        "workflow": "sha256:b6b8c87fc5f9615c193594c7a861a59e55022acfdb1dc9970c903af9fca22dee",
    },
    "sdk004": {
        "commit": "67b879ba596be7239abb26c1492a22ac546cc61e",
        "goldenVector": "sha256:0a8ddc461b62c025d15fae36aa0001e97c653f9f20be17bd53a76a192eef461c",
        "modules": {
            "__init__.py": "sha256:732b23800d5f8f2a8e449f8b71c18990281958380ff61c90306fd133606bd347",
            "_json.py": "sha256:26accb104905617cb6f266634fd5cd8e122c8022636d5b0261f3b472e748b240",
            "cloudevents.py": "sha256:110f1a5559093a4cbfd2377eb5f38bae37eafa3af677fce74f69132eb9c67451",
            "errors.py": "sha256:9be30cf4135bd56c6785f96ee1d57207b541921dcbd9ae5b091283734d5760ab",
        },
    },
    "trust001": {
        "client": "sha256:128c6b3fafd03aabcec139bf43be73df8cad0a781d0075b88d3d218a377b5175",
        "commit": "73802adbfa1adf97f20d03026e0b2232691d5392",
        "request": "sha256:dc2cac458329174a1ac4feda9182f0f4c355dd054278f343b9784702aaff4c75",
        "response": "sha256:2811621092f603b8fc6f73ddba7e6921481c66ed385eaec33287b385947013b4",
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"prefetch refused: {message}")


def git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *arguments], cwd=ROOT, text=True, capture_output=True, shell=False, check=False)


def main() -> None:
    require(sys.version_info[:3] == (3, 12, 14), f"CPython 3.12.14 required, got {sys.version.split()[0]}")
    locks = json.loads((ROOT / "contract-mocks/upstream-locks.json").read_text(encoding="utf-8"))
    require(locks == EXPECTED_LOCKS, "immutable predecessor lock mismatch")
    require(git("cat-file", "-e", f"{BASE}^{{commit}}").returncode == 0, "empty base commit is unavailable")
    require(git("merge-base", "--is-ancestor", BASE, "HEAD").returncode == 0, "HEAD is not descended from the exact empty base")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    require(project["project"]["requires-python"] == "==3.12.*", "Python contract drift")
    require(project["project"]["dependencies"] == [], "KN-001 must have no dependency")
    require(project["build-system"]["requires"] == [], "build system must have no dependency")
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    require(lock["requires-python"] == "==3.12.*", "lock Python contract drift")
    require(lock["package"] == [{"name": "planeon-harness-knowledge-plane", "version": "0.1.0", "source": {"editable": "."}}], "uv.lock is not the one-package root closure")
    required = [
        "PORTING.yaml", "ci/run_make_target.py", "ci/run_packet_argv.py",
        "ci/targets/kn-001.json", "ci/verify-offline.sh",
        "src/planeon_knowledge/common/canonical.py",
        *[f"migrations/{schema}/001_foundation.sql" for schema in ("domain", "ingestion", "retrieval", "memory")],
        *[f"services/{service}/Containerfile" for service in ("domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker", "memory-service")],
        *[f"deploy/helm/{service}/Chart.yaml" for service in ("domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker", "memory-service")],
    ]
    for relative in required:
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"required regular source is missing: {relative}")
    print("prefetch passed: exact locks, CPython 3.12.14, one-package standard-library closure, and local source are present")


if __name__ == "__main__":
    main()
