"""Worker composition boundary; connector and staging ports are always injected."""

from dataclasses import dataclass

from planeon_knowledge.common.asgi import closed_failure_probes, create_health_app
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS
from planeon_knowledge.ingestion.service import IngestionService, ReadinessService


@dataclass(frozen=True, slots=True)
class ReadinessWorker:
    """Non-HTTP worker boundary exposing only fenced readiness work operations."""

    service: ReadinessService

    def claim(self, *args, **kwargs):
        return self.service.claim_assessment_work(*args, **kwargs)

    def process(self, *args, **kwargs):
        return self.service.complete_assessment_work(*args, **kwargs)

    def record_failure(self, *args, **kwargs):
        return self.service.record_assessment_failure(*args, **kwargs)


def create_worker(service: IngestionService) -> IngestionService:
    return service


def create_readiness_worker(service: ReadinessService) -> ReadinessWorker:
    return ReadinessWorker(service)

app = create_health_app(SERVICE_DESCRIPTORS["ingest-worker"], closed_failure_probes())
