# Sol-High Product Execution Rules

1. Implement exactly one authorized task packet per branch and pull request.
2. Touch only that packet's `allowedPaths`; preserve every predecessor lock.
3. Never open, mount, copy, adapt, translate, or execute a warm-start checkout.
4. Use only the signed external offline launcher and direct-argv packet transport.
5. Never add hosted runners, billable services, API keys, cloud provisioning,
   runtime downloads, mutable artifact references, or external telemetry defaults.
6. Preserve source, unit, PR, merge, artifact, release, deployment, runtime,
   security, assurance, and tenant acceptance as separate evidence states.
7. `KN-001` alone owns the root `Makefile`, `ci/run_make_target.py`, and inert
   `PORTING.yaml`; later packets add only their packet-local target descriptors.
