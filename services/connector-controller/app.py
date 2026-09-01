"""Controller composition boundary; production dependencies remain externally injected."""

from planeon_knowledge.common.asgi import closed_failure_probes, create_health_app
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS
from planeon_knowledge.ingestion.asgi import (
    DependencyProvider,
    IdentityProvider,
    IngestionAsgiApplication,
    PermitProvider,
)
from planeon_knowledge.ingestion.service import IngestionService


def create_application(
    service: IngestionService,
    identity_provider: IdentityProvider,
    permit_provider: PermitProvider,
    dependency_provider: DependencyProvider,
) -> IngestionAsgiApplication:
    return IngestionAsgiApplication(
        service,
        identity_provider,
        permit_provider,
        dependency_provider,
    )

app = create_health_app(SERVICE_DESCRIPTORS["connector-controller"], closed_failure_probes())
