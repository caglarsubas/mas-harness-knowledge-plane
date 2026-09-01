"""Controller composition boundary; production dependencies remain externally injected."""

from planeon_knowledge.common.asgi import closed_failure_probes, create_health_app
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS
from planeon_knowledge.ingestion.asgi import (
    DependencyProvider,
    IdentityProvider,
    IngestionAsgiApplication,
    PermitProvider,
    ReadinessDependencyProvider,
)
from planeon_knowledge.ingestion.service import IngestionService, ReadinessService


def create_application(
    service: IngestionService,
    identity_provider: IdentityProvider,
    permit_provider: PermitProvider,
    dependency_provider: DependencyProvider,
    readiness_service: ReadinessService | None = None,
    readiness_dependency_provider: ReadinessDependencyProvider | None = None,
) -> IngestionAsgiApplication:
    return IngestionAsgiApplication(
        service,
        identity_provider,
        permit_provider,
        dependency_provider,
        readiness_service,
        readiness_dependency_provider,
    )

app = create_health_app(SERVICE_DESCRIPTORS["connector-controller"], closed_failure_probes())
