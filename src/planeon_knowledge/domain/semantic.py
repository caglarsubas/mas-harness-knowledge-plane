"""Bounded, non-dereferencing RDFLib and pySHACL validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib.metadata import version as package_version
from time import monotonic
from typing import Callable

from pyshacl import validate as shacl_validate
from rdflib import BNode, Graph, Literal, URIRef
from rdflib.compare import to_canonical_graph
from rdflib.namespace import OWL, RDF, RDFS, SH, XSD

from planeon_knowledge.common.canonical import canonical_digest
from .contracts import (
    CompatibilityReport,
    CompatibilityState,
    Finding,
    ValidationReport,
)

MAX_DOCUMENT = 2 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_DATA_TRIPLES = 50_000
MAX_SHAPE_TRIPLES = 20_000
MAX_FINDINGS = 128
MAX_SECONDS = 30.0
MEDIA_TYPES = {"text/turtle": "turtle", "application/ld+json": "json-ld"}
W3C_PREFIXES = (
    str(RDF), str(RDFS), str(XSD), str(OWL), str(SH),
)
FORBIDDEN_SHAPE_TERMS = {
    URIRef(str(SH) + "sparql"),
    URIRef(str(SH) + "js"),
    URIRef(str(SH) + "jsFunctionName"),
    URIRef(str(SH) + "rule"),
    URIRef(str(SH) + "rules"),
    URIRef(str(SH) + "SPARQLConstraint"),
    URIRef(str(SH) + "SPARQLConstraintComponent"),
    URIRef(str(SH) + "JSConstraint"),
    URIRef(str(SH) + "JSConstraintComponent"),
}
SAFE_MODES = {
    "advanced": False,
    "js": False,
    "inference": "none",
    "doOwlImports": False,
    "abortOnFirst": False,
    "metaShacl": False,
}


class SemanticFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class SemanticMaterial:
    ontology: bytes
    shapes: bytes
    data: bytes
    ontology_media_type: str = "text/turtle"
    shapes_media_type: str = "text/turtle"
    data_media_type: str = "text/turtle"

    def __post_init__(self) -> None:
        for value in (self.ontology, self.shapes, self.data):
            if not isinstance(value, bytes):
                raise SemanticFailure("MATERIAL_TYPE_INVALID")
        for media_type in (self.ontology_media_type, self.shapes_media_type, self.data_media_type):
            if media_type not in MEDIA_TYPES:
                raise SemanticFailure("MEDIA_TYPE_UNSUPPORTED")


@dataclass(frozen=True, slots=True)
class SemanticSnapshot:
    report: ValidationReport
    term_statements: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if self.term_statements != tuple(sorted(set(self.term_statements))):
            raise ValueError("term statements must be sorted and unique")

    @property
    def terms(self) -> frozenset[str]:
        return frozenset(term for term, _digest in self.term_statements)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SemanticFailure("JSON_DUPLICATE_MEMBER")
        result[key] = value
    return result


def _inspect_jsonld(value: object) -> None:
    if isinstance(value, dict):
        if "@import" in value:
            raise SemanticFailure("JSONLD_IMPORT_FORBIDDEN")
        if "@context" in value:
            context = value["@context"]
            if isinstance(context, str) or not isinstance(context, (dict, list)):
                raise SemanticFailure("JSONLD_REMOTE_CONTEXT_FORBIDDEN")
            if isinstance(context, list) and any(not isinstance(item, dict) for item in context):
                raise SemanticFailure("JSONLD_REMOTE_CONTEXT_FORBIDDEN")
        for child in value.values():
            _inspect_jsonld(child)
    elif isinstance(value, list):
        for child in value:
            _inspect_jsonld(child)


def _preflight_jsonld(raw: bytes) -> None:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
    except SemanticFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticFailure("JSONLD_INVALID") from exc
    _inspect_jsonld(value)


def _iri_allowed(value: str, domain_id: str) -> bool:
    return value.startswith(f"urn:planeon:{domain_id}:") or any(value.startswith(prefix) for prefix in W3C_PREFIXES)


def _term_text(value: object) -> str:
    if isinstance(value, URIRef):
        return f"<{value}>"
    if isinstance(value, Literal):
        return value.n3()
    if isinstance(value, BNode):
        return f"_:{value}"
    return str(value)


def _graph_digest(graph: Graph) -> str:
    canonical = to_canonical_graph(graph)
    lines = sorted(f"{_term_text(subject)} {_term_text(predicate)} {_term_text(obj)} ." for subject, predicate, obj in canonical)
    return canonical_digest(lines)


def _check_deadline(started: float, clock: Callable[[], float]) -> None:
    if clock() - started > MAX_SECONDS:
        raise SemanticFailure("VALIDATION_DEADLINE_EXCEEDED")


def _parse(raw: bytes, media_type: str, *, domain_id: str, limit: int, started: float, clock: Callable[[], float]) -> Graph:
    if media_type not in MEDIA_TYPES:
        raise SemanticFailure("MEDIA_TYPE_UNSUPPORTED")
    if not isinstance(raw, bytes) or len(raw) > MAX_DOCUMENT:
        raise SemanticFailure("DOCUMENT_SIZE_EXCEEDED")
    if media_type == "application/ld+json":
        _preflight_jsonld(raw)
    _check_deadline(started, clock)
    graph = Graph()
    try:
        graph.parse(data=raw, format=MEDIA_TYPES[media_type], publicID=None)
    except Exception as exc:
        raise SemanticFailure("RDF_PARSE_FAILED") from exc
    _check_deadline(started, clock)
    if len(graph) > limit:
        raise SemanticFailure("TRIPLE_LIMIT_EXCEEDED")
    for subject, predicate, obj in graph:
        for term in (subject, predicate, obj):
            if isinstance(term, URIRef) and not _iri_allowed(str(term), domain_id):
                raise SemanticFailure("IRI_NOT_ALLOWLISTED")
            if isinstance(term, Literal):
                if term.datatype is not None and not _iri_allowed(str(term.datatype), domain_id):
                    raise SemanticFailure("IRI_NOT_ALLOWLISTED")
                lowered = str(term).casefold()
                if "javascript:" in lowered or "<script" in lowered or "#!/" in lowered:
                    raise SemanticFailure("EXECUTABLE_LITERAL_FORBIDDEN")
        if predicate == OWL.imports:
            raise SemanticFailure("OWL_IMPORT_FORBIDDEN")
    return graph


def _reject_unsafe_shapes(graph: Graph) -> None:
    for subject, predicate, obj in graph:
        if predicate in FORBIDDEN_SHAPE_TERMS or obj in FORBIDDEN_SHAPE_TERMS:
            raise SemanticFailure("SHACL_EXECUTABLE_FEATURE_FORBIDDEN")
        if predicate == RDF.type and isinstance(obj, URIRef) and ("SPARQL" in str(obj) or "JSConstraint" in str(obj)):
            raise SemanticFailure("SHACL_EXECUTABLE_FEATURE_FORBIDDEN")


def _reason_component(value: object) -> str:
    local = re.split(r"[#/]", str(value))[-1]
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", local).strip("_").upper() or "UNKNOWN"
    return f"SHACL_{normalized}"[:128]


def _term_digest(value: object | None) -> str:
    return canonical_digest({"term": "" if value is None else _term_text(value)})


def _findings(report_graph: Graph) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for result in report_graph.subjects(RDF.type, SH.ValidationResult):
        severity_value = report_graph.value(result, SH.resultSeverity)
        severity = "VIOLATION" if severity_value == SH.Violation else "WARNING" if severity_value == SH.Warning else "INFO"
        component = report_graph.value(result, SH.sourceConstraintComponent)
        results.append(
            Finding(
                reason_code=_reason_component(component),
                severity=severity,
                focus_digest=_term_digest(report_graph.value(result, SH.focusNode)),
                path_digest=_term_digest(report_graph.value(result, SH.resultPath)),
                constraint_component=_reason_component(component),
            )
        )
    ordered = tuple(sorted(results, key=lambda item: (item.reason_code, item.focus_digest, item.path_digest, item.constraint_component)))
    if len(ordered) > MAX_FINDINGS:
        raise SemanticFailure("FINDING_LIMIT_EXCEEDED")
    return ordered


def _term_statements(ontology: Graph) -> tuple[tuple[str, str], ...]:
    canonical = to_canonical_graph(ontology)
    term_types = {RDFS.Class, OWL.Class, RDF.Property, OWL.ObjectProperty, OWL.DatatypeProperty}
    terms = sorted({subject for subject, _predicate, obj in canonical.triples((None, RDF.type, None)) if isinstance(subject, URIRef) and obj in term_types}, key=str)
    result: list[tuple[str, str]] = []
    for term in terms:
        statements = sorted(f"{_term_text(subject)} {_term_text(predicate)} {_term_text(obj)} ." for subject, predicate, obj in canonical.triples((term, None, None)))
        result.append((str(term), canonical_digest(statements)))
    return tuple(result)


def _inventory_body(values: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    return [{"term": term, "statementDigest": statement_digest} for term, statement_digest in values]


def classify_compatibility(prior: tuple[tuple[str, str], ...], candidate: tuple[tuple[str, str], ...]) -> CompatibilityReport:
    prior_map = dict(prior)
    candidate_map = dict(candidate)
    removed = set(prior_map) - set(candidate_map)
    changed = {term for term in prior_map.keys() & candidate_map if prior_map[term] != candidate_map[term]}
    added = set(candidate_map) - set(prior_map)
    state = CompatibilityState.BREAKING if removed or changed else CompatibilityState.BACKWARD_COMPATIBLE if added else CompatibilityState.IDENTICAL
    return CompatibilityReport(
        state,
        canonical_digest(_inventory_body(prior)),
        canonical_digest(_inventory_body(candidate)),
        canonical_digest(sorted(removed | changed | added)),
    )


class SemanticValidator:
    def __init__(self, *, clock: Callable[[], float] = monotonic) -> None:
        self._clock = clock

    @staticmethod
    def engine_versions() -> dict[str, str]:
        return {"rdflib": package_version("rdflib"), "pyshacl": package_version("pyshacl")}

    def validate(
        self,
        *,
        organization_id: str,
        domain_id: str,
        version: str,
        package_digest: str,
        expected_ontology_digest: str,
        expected_shapes_digest: str,
        material: SemanticMaterial,
        started_at: str,
        completed_at: str,
    ) -> SemanticSnapshot:
        if len(material.ontology) + len(material.shapes) + len(material.data) > MAX_TOTAL:
            raise SemanticFailure("TOTAL_SIZE_EXCEEDED")
        if f"sha256:{hashlib.sha256(material.ontology).hexdigest()}" != expected_ontology_digest or f"sha256:{hashlib.sha256(material.shapes).hexdigest()}" != expected_shapes_digest:
            raise SemanticFailure("MATERIAL_DIGEST_MISMATCH")
        versions = self.engine_versions()
        if versions != {"rdflib": "7.6.0", "pyshacl": "0.40.1"}:
            raise SemanticFailure("SEMANTIC_ENGINE_MISMATCH")
        started = self._clock()
        ontology = _parse(material.ontology, material.ontology_media_type, domain_id=domain_id, limit=MAX_DATA_TRIPLES, started=started, clock=self._clock)
        data = _parse(material.data, material.data_media_type, domain_id=domain_id, limit=MAX_DATA_TRIPLES, started=started, clock=self._clock)
        shapes = _parse(material.shapes, material.shapes_media_type, domain_id=domain_id, limit=MAX_SHAPE_TRIPLES, started=started, clock=self._clock)
        _reject_unsafe_shapes(shapes)
        combined = ontology + data
        if len(combined) > MAX_DATA_TRIPLES:
            raise SemanticFailure("TRIPLE_LIMIT_EXCEEDED")
        _check_deadline(started, self._clock)
        try:
            conforms, report_graph, _report_text = shacl_validate(
                combined,
                shacl_graph=shapes,
                ont_graph=None,
                advanced=False,
                inference="none",
                inplace=False,
                abort_on_first=False,
                allow_infos=False,
                allow_warnings=False,
                meta_shacl=False,
                sparql_mode=False,
                js=False,
                do_owl_imports=False,
            )
        except Exception as exc:
            raise SemanticFailure("SHACL_ENGINE_FAILED") from exc
        _check_deadline(started, self._clock)
        findings = _findings(report_graph)
        terms = _term_statements(ontology)
        report_body = {
            "organizationId": organization_id,
            "domainId": domain_id,
            "version": version,
            "packageDigest": package_digest,
            "graphDigest": _graph_digest(combined),
            "shapesDigest": _graph_digest(shapes),
            "engineVersionsDigest": canonical_digest(versions),
            "modeDigest": canonical_digest(SAFE_MODES),
            "conforms": bool(conforms),
            "dataTriples": len(combined),
            "shapeTriples": len(shapes),
            "findings": [finding.__dict__ if hasattr(finding, "__dict__") else {
                "reasonCode": finding.reason_code,
                "severity": finding.severity,
                "focusDigest": finding.focus_digest,
                "pathDigest": finding.path_digest,
                "constraintComponent": finding.constraint_component,
            } for finding in findings],
            "termInventoryDigest": canonical_digest(_inventory_body(terms)),
            "startedAt": started_at,
            "completedAt": completed_at,
        }
        report_digest = canonical_digest(report_body)
        report = ValidationReport(
            organization_id=organization_id,
            domain_id=domain_id,
            version=version,
            package_digest=package_digest,
            graph_digest=report_body["graphDigest"],
            shapes_digest=report_body["shapesDigest"],
            engine_versions_digest=report_body["engineVersionsDigest"],
            mode_digest=report_body["modeDigest"],
            conforms=bool(conforms),
            data_triples=len(combined),
            shape_triples=len(shapes),
            findings=findings,
            term_inventory_digest=report_body["termInventoryDigest"],
            started_at=started_at,
            completed_at=completed_at,
            report_digest=report_digest,
        )
        return SemanticSnapshot(report, terms)
