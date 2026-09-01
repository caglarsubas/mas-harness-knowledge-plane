from planeon_knowledge.common.asgi import closed_failure_probes, create_health_app
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS

app = create_health_app(SERVICE_DESCRIPTORS["index-worker"], closed_failure_probes())
