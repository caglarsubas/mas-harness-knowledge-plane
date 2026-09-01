"""Worker composition boundary; connector and staging ports are always injected."""

from planeon_knowledge.common.asgi import closed_failure_probes, create_health_app
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS
from planeon_knowledge.ingestion.service import IngestionService


def create_worker(service: IngestionService) -> IngestionService:
    return service

app = create_health_app(SERVICE_DESCRIPTORS["ingest-worker"], closed_failure_probes())
