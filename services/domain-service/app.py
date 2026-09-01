from importlib.metadata import version

from planeon_knowledge.common.asgi import create_health_app
from planeon_knowledge.common.health import DependencyHealth, HealthState
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS

CHECKED_AT = "2000-01-01T00:00:00Z"


def unavailable(name: str):
    def probe():
        raise RuntimeError(f"{name} must be injected")
    return probe


def semantic_engine_probe():
    ready = version("rdflib") == "7.6.0" and version("pyshacl") == "0.40.1"
    return DependencyHealth("contract-mock", HealthState.READY if ready else HealthState.NOT_READY, CHECKED_AT, "SEMANTIC_ENGINE_READY" if ready else "SEMANTIC_ENGINE_MISMATCH")


app = create_health_app(SERVICE_DESCRIPTORS["domain-service"], {
    "identity-admission": unavailable("identity-admission"),
    "policy": unavailable("policy"),
    "contract-mock": semantic_engine_probe,
    "owned-store": unavailable("owned-store"),
    "telemetry": unavailable("telemetry"),
})
