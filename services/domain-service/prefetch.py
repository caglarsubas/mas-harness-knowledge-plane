#!/usr/bin/env python3
"""Verify the already-installed semantic closure without resolving packages."""

from __future__ import annotations

import json
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PACKAGES = {
    "html5rdf": ("1.2.1", "1f519121bc366af3e485310dc8041d2e86e5173c1a320fac3dc9d2604069b83e"),
    "owlrl": ("7.6.2", "83347bf7f133979e87b2b18695d51d25510b99cec3f6919b5df05d4fbf058ae0"),
    "packaging": ("26.3", "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"),
    "prettytable": ("3.18.0", "b3346e0e6f79180833aebaac088ae926340586cf6d7d991b9eb125b65f72313a"),
    "pyparsing": ("3.3.2", "850ba148bd908d7e2411587e247a1e4f0327839c40e2e5e6d05a007ecc69911d"),
    "pyshacl": ("0.40.1", "27dd58c8ddfa103303b4a8c40b2c666332ffc912dbcd3137f7adc7b7bc5e6bda"),
    "rdflib": ("7.6.0", "30c0a3ebf4c0e09215f066be7246794b6492e054e782d7ac2a34c9f70a15e0dd"),
    "wcwidth": ("0.8.3", "d5b73dba6158a595ec9370350e7f2637bcac8d6c5e4fde34f30fcffb6103a5e4"),
}
EXPECTED_INVENTORIES = {
    "toolchainInventorySha256": "b1db59b19689e240d1224f0a116f19072a10f0cc8baa5ba34a30cdd37feb896a",
    "wheelhouseInventorySha256": "79f00f38eca25736612634e31b0a3909c1f34af7ffd18bafbc9292a3c6691957",
    "licenseInventorySha256": "d4875eb83cfca4774fd0c84f91647bda759cc32cd0beb75191600c68894f7951",
}
EXPECTED_LICENSES = {
    "html5rdf": "MIT",
    "owlrl": "W3C-20150513",
    "packaging": "Apache-2.0 OR BSD-2-Clause",
    "prettytable": "BSD-3-Clause",
    "pyparsing": "MIT",
    "pyshacl": "Apache-2.0",
    "rdflib": "BSD-3-Clause",
    "wcwidth": "MIT",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"semantic prefetch refused: {message}")


def main() -> None:
    require(sys.version_info[:3] == (3, 12, 14), f"CPython 3.12.14 required, got {sys.version.split()[0]}")
    lock = json.loads((ROOT / "services/domain-service/dependencies.lock.json").read_text(encoding="utf-8"))
    require(set(lock) == {"schemaVersion", "python", "packages", *EXPECTED_INVENTORIES}, "dependency lock is not closed")
    require(lock["schemaVersion"] == "planeon.knowledge.semantic-dependencies/v1" and lock["python"] == "3.12.14", "dependency lock runtime drift")
    require(all(lock[name] == expected for name, expected in EXPECTED_INVENTORIES.items()), "root-owned inventory binding drift")
    packages = lock["packages"]
    require(isinstance(packages, list) and len(packages) == len(EXPECTED_PACKAGES), "dependency closure cardinality drift")
    observed: dict[str, tuple[str, str, str]] = {}
    for item in packages:
        require(isinstance(item, dict) and set(item) == {"license", "name", "sha256", "version", "wheel"}, "package lock member drift")
        name = item["name"]
        require(name in EXPECTED_PACKAGES and name not in observed, "unknown or duplicate dependency")
        expected_version, expected_sha = EXPECTED_PACKAGES[name]
        require(item["version"] == expected_version and item["sha256"] == expected_sha, f"locked artifact mismatch: {name}")
        require(item["license"] == EXPECTED_LICENSES[name], f"license disposition mismatch: {name}")
        require(item["wheel"].endswith(".whl") and "/" not in item["wheel"] and "\\" not in item["wheel"], f"wheel filename is unsafe: {name}")
        observed[name] = (item["version"], item["sha256"], item["license"])
    require(set(observed) == set(EXPECTED_PACKAGES), "dependency closure is incomplete")
    project = tomllib.loads((ROOT / "services/domain-service/pyproject.toml").read_text(encoding="utf-8"))
    expected_dependencies = [f"{name}=={EXPECTED_PACKAGES[name][0]}" for name in EXPECTED_PACKAGES]
    require(project["project"]["requires-python"] == "==3.12.*", "service Python range drift")
    require(project["project"]["dependencies"] == expected_dependencies, "service dependency manifest drift")
    require(project["tool"]["planeon"] == {"provider": "planeon.rdflib+planeon.pyshacl", "network": "disabled", "imports": "none", "jena": "PROVIDER_UNAVAILABLE"}, "semantic provider contract drift")
    for name, (expected_version, _sha) in EXPECTED_PACKAGES.items():
        try:
            installed = version(name)
        except PackageNotFoundError as exc:
            raise SystemExit(f"semantic prefetch refused: installed package missing: {name}") from exc
        require(installed == expected_version, f"installed version mismatch: {name}")
    print("semantic prefetch passed: exact CPython, eight-package lock, inventories, licenses, and installed versions are present")


if __name__ == "__main__":
    main()
