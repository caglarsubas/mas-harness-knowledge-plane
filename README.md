# Planeon Knowledge Plane

This repository owns the Domain & Semantic, Data Integration & Provenance,
Retrieval & Context Engineering, and Memory & State harnesses.

KN-001 is the dependency-minimal foundation: common closed records, six
health-only service shells, four isolated SQL ownership domains, privacy-safe
local mocks, and inert image/chart source. It intentionally implements no domain,
connector, ingestion, retrieval, indexing, or memory business behavior.

## Offline verification

The trusted host launcher reads the hash-pinned KN-001 packet and invokes the
repository adapter inside one OS-enforced deny-all-outbound process tree. Direct
execution of acceptance commands is not authorized.

```text
/opt/planeon/bin/harness-offline-launch
```

`make prefetch`, `make common-contract`, and `make security` are packet-owned
targets. They are shown for contract discovery, not as a bypass around the
trusted launcher.

## Evidence boundary

KN-001 can establish source, offline contract/unit, pull-request, and merge
evidence. PostgreSQL execution, images, SBOMs, releases, deployments, runtime,
live security, assurance, and tenant acceptance remain pending or
`NOT_RUN_ENV_UNAVAILABLE`.
