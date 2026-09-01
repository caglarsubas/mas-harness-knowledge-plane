BEGIN;

SET LOCAL ROLE planeon_kn_domain_owner;

CREATE TABLE domain.domain_definition (
    organization_id uuid NOT NULL,
    domain_id text NOT NULL,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    default_language text NOT NULL,
    supported_languages text[] NOT NULL,
    business_owner_ids text[] NOT NULL,
    data_owner_ids text[] NOT NULL,
    compatibility_mode text NOT NULL CHECK (compatibility_mode IN ('BACKWARD', 'STRICT')),
    created_at timestamptz NOT NULL,
    created_by_subject_id text NOT NULL,
    PRIMARY KEY (organization_id, domain_id)
);

CREATE TABLE domain.domain_version (
    organization_id uuid NOT NULL,
    domain_id text NOT NULL,
    version text NOT NULL,
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    ontology_digest text NOT NULL CHECK (ontology_digest ~ '^sha256:[0-9a-f]{64}$'),
    shapes_digest text NOT NULL CHECK (shapes_digest ~ '^sha256:[0-9a-f]{64}$'),
    import_manifest_digest text NOT NULL CHECK (import_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    owners_digest text NOT NULL CHECK (owners_digest ~ '^sha256:[0-9a-f]{64}$'),
    license_expression text NOT NULL CHECK (license_expression = 'Apache-2.0'),
    created_at timestamptz NOT NULL,
    created_by_subject_id text NOT NULL,
    PRIMARY KEY (organization_id, domain_id, version),
    FOREIGN KEY (organization_id, domain_id) REFERENCES domain.domain_definition (organization_id, domain_id)
);

CREATE TABLE domain.domain_version_revision (
    organization_id uuid NOT NULL,
    domain_id text NOT NULL,
    version text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('DRAFT', 'VALIDATING', 'VALID', 'INVALID', 'AWAITING_APPROVAL', 'ACTIVE', 'REJECTED', 'SUPERSEDED', 'RETIRED')),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, domain_id, version, revision),
    FOREIGN KEY (organization_id, domain_id, version) REFERENCES domain.domain_version (organization_id, domain_id, version)
);

CREATE TABLE domain.semantic_mapping (
    organization_id uuid NOT NULL,
    mapping_id text NOT NULL,
    version text NOT NULL,
    domain_version_digest text NOT NULL CHECK (domain_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_schema_digest text NOT NULL CHECK (source_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    assertions_digest text NOT NULL CHECK (assertions_digest ~ '^sha256:[0-9a-f]{64}$'),
    owners_digest text NOT NULL CHECK (owners_digest ~ '^sha256:[0-9a-f]{64}$'),
    provenance_digest text NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    created_by_subject_id text NOT NULL,
    PRIMARY KEY (organization_id, mapping_id, version)
);

CREATE TABLE domain.semantic_mapping_revision (
    organization_id uuid NOT NULL,
    mapping_id text NOT NULL,
    version text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('DRAFT', 'VALIDATING', 'VALID', 'INVALID', 'AWAITING_APPROVAL', 'ACTIVE', 'REJECTED', 'SUPERSEDED')),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, mapping_id, version, revision),
    FOREIGN KEY (organization_id, mapping_id, version) REFERENCES domain.semantic_mapping (organization_id, mapping_id, version)
);

CREATE TABLE domain.validation_report (
    organization_id uuid NOT NULL,
    aggregate_kind text NOT NULL CHECK (aggregate_kind IN ('DOMAIN_VERSION', 'SEMANTIC_MAPPING')),
    aggregate_id text NOT NULL,
    version text NOT NULL,
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    graph_digest text NOT NULL CHECK (graph_digest ~ '^sha256:[0-9a-f]{64}$'),
    shapes_digest text NOT NULL CHECK (shapes_digest ~ '^sha256:[0-9a-f]{64}$'),
    engine_versions_digest text NOT NULL CHECK (engine_versions_digest ~ '^sha256:[0-9a-f]{64}$'),
    mode_digest text NOT NULL CHECK (mode_digest ~ '^sha256:[0-9a-f]{64}$'),
    term_inventory_digest text NOT NULL CHECK (term_inventory_digest ~ '^sha256:[0-9a-f]{64}$'),
    findings_digest text NOT NULL CHECK (findings_digest ~ '^sha256:[0-9a-f]{64}$'),
    conforms boolean NOT NULL,
    data_triples integer NOT NULL CHECK (data_triples BETWEEN 0 AND 50000),
    shape_triples integer NOT NULL CHECK (shape_triples BETWEEN 0 AND 20000),
    finding_count integer NOT NULL CHECK (finding_count BETWEEN 0 AND 128),
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    report_digest text NOT NULL CHECK (report_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, aggregate_kind, aggregate_id, version, report_digest)
);

CREATE TABLE domain.domain_evidence (
    organization_id uuid NOT NULL,
    aggregate_id text NOT NULL,
    version text NOT NULL,
    state text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    report_digest text CHECK (report_digest IS NULL OR report_digest ~ '^sha256:[0-9a-f]{64}$'),
    approval_evidence_digest text CHECK (approval_evidence_digest IS NULL OR approval_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    compatibility_digest text CHECK (compatibility_digest IS NULL OR compatibility_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, record_digest)
);

CREATE TABLE domain.domain_event_outbox (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL,
    resource_digest text NOT NULL CHECK (resource_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    occurred_at timestamptz NOT NULL,
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, event_id),
    UNIQUE (organization_id, event_digest)
);

CREATE TABLE domain.domain_idempotency (
    organization_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    response_digest text NOT NULL CHECK (response_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, idempotency_key)
);

CREATE TABLE domain.active_domain_pointer (
    organization_id uuid NOT NULL,
    domain_id text NOT NULL,
    version text NOT NULL,
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    activated_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, domain_id),
    FOREIGN KEY (organization_id, domain_id, version) REFERENCES domain.domain_version (organization_id, domain_id, version)
);

ALTER TABLE domain.domain_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_definition FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_version FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_version_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_version_revision FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.semantic_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.semantic_mapping FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.semantic_mapping_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.semantic_mapping_revision FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.validation_report ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.validation_report FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_event_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.domain_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE domain.active_domain_pointer ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain.active_domain_pointer FORCE ROW LEVEL SECURITY;

CREATE POLICY domain_definition_tenant ON domain.domain_definition USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY domain_version_tenant ON domain.domain_version USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY domain_version_revision_tenant ON domain.domain_version_revision USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY semantic_mapping_tenant ON domain.semantic_mapping USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY semantic_mapping_revision_tenant ON domain.semantic_mapping_revision USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY validation_report_tenant ON domain.validation_report USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY domain_evidence_tenant ON domain.domain_evidence USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY domain_event_outbox_tenant ON domain.domain_event_outbox USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY domain_idempotency_tenant ON domain.domain_idempotency USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY active_domain_pointer_tenant ON domain.active_domain_pointer USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);

CREATE TRIGGER domain_definition_append_only BEFORE UPDATE OR DELETE ON domain.domain_definition FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER domain_version_append_only BEFORE UPDATE OR DELETE ON domain.domain_version FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER domain_version_revision_append_only BEFORE UPDATE OR DELETE ON domain.domain_version_revision FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER semantic_mapping_append_only BEFORE UPDATE OR DELETE ON domain.semantic_mapping FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER semantic_mapping_revision_append_only BEFORE UPDATE OR DELETE ON domain.semantic_mapping_revision FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER validation_report_append_only BEFORE UPDATE OR DELETE ON domain.validation_report FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER domain_evidence_append_only BEFORE UPDATE OR DELETE ON domain.domain_evidence FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER domain_event_outbox_append_only BEFORE UPDATE OR DELETE ON domain.domain_event_outbox FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();
CREATE TRIGGER domain_idempotency_append_only BEFORE UPDATE OR DELETE ON domain.domain_idempotency FOR EACH ROW EXECUTE FUNCTION domain.reject_mutation();

CREATE FUNCTION domain.activate_domain_version(
    p_organization_id uuid,
    p_domain_id text,
    p_version text,
    p_expected_revision bigint,
    p_idempotency_key text,
    p_request_digest text,
    p_response_digest text,
    p_package_digest text,
    p_report_digest text,
    p_approval_evidence_digest text,
    p_compatibility_digest text,
    p_correlation_id uuid,
    p_event_id uuid,
    p_evidence_record_digest text,
    p_event_digest text,
    p_prior_event_id uuid,
    p_prior_evidence_record_digest text,
    p_prior_event_digest text,
    p_occurred_at timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    active_row domain.active_domain_pointer%ROWTYPE;
    current_revision domain.domain_version_revision%ROWTYPE;
BEGIN
    IF p_organization_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    IF p_package_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_request_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_response_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_report_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_approval_evidence_digest !~ '^sha256:[0-9a-f]{64}$'
       OR p_compatibility_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'digest binding mismatch';
    END IF;
    IF EXISTS (
        SELECT 1 FROM domain.domain_idempotency AS prior_command
        WHERE prior_command.organization_id = p_organization_id
          AND prior_command.idempotency_key = p_idempotency_key
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM domain.domain_idempotency AS prior_command
            WHERE prior_command.organization_id = p_organization_id
              AND prior_command.idempotency_key = p_idempotency_key
              AND prior_command.request_digest = p_request_digest
              AND prior_command.response_digest = p_response_digest
        ) THEN
            RAISE EXCEPTION 'idempotency conflict';
        END IF;
        RETURN;
    END IF;
    SELECT revision.* INTO STRICT current_revision
      FROM domain.domain_version_revision AS revision
      WHERE revision.organization_id = p_organization_id
        AND revision.domain_id = p_domain_id
        AND revision.version = p_version
      ORDER BY revision.revision DESC LIMIT 1 FOR UPDATE;
    IF current_revision.revision <> p_expected_revision OR current_revision.state NOT IN ('AWAITING_APPROVAL', 'SUPERSEDED') THEN
        RAISE EXCEPTION 'state or revision mismatch';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM domain.domain_version AS candidate
        JOIN domain.validation_report AS report
          ON report.organization_id = candidate.organization_id
         AND report.aggregate_kind = 'DOMAIN_VERSION'
         AND report.aggregate_id = candidate.domain_id
         AND report.version = candidate.version
        WHERE candidate.organization_id = p_organization_id
          AND candidate.domain_id = p_domain_id
          AND candidate.version = p_version
          AND candidate.package_digest = p_package_digest
          AND report.report_digest = p_report_digest
          AND report.conforms
    ) OR NOT EXISTS (
        SELECT 1 FROM domain.domain_evidence AS evidence
        WHERE evidence.organization_id = p_organization_id
          AND evidence.aggregate_id = p_domain_id
          AND evidence.version = p_version
          AND evidence.approval_evidence_digest = p_approval_evidence_digest
    ) THEN
        RAISE EXCEPTION 'approval or validation binding missing';
    END IF;
    SELECT pointer.* INTO active_row
      FROM domain.active_domain_pointer AS pointer
      WHERE pointer.organization_id = p_organization_id AND pointer.domain_id = p_domain_id
      FOR UPDATE;
    IF FOUND AND active_row.version = p_version THEN
        RAISE EXCEPTION 'version already active';
    END IF;
    IF FOUND THEN
        IF p_prior_event_id IS NULL OR p_prior_evidence_record_digest IS NULL OR p_prior_event_digest IS NULL
           OR p_prior_evidence_record_digest !~ '^sha256:[0-9a-f]{64}$' OR p_prior_event_digest !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'prior-version evidence binding missing';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM domain.domain_version_revision AS prior_revision
            WHERE prior_revision.organization_id = p_organization_id
              AND prior_revision.domain_id = p_domain_id
              AND prior_revision.version = active_row.version
              AND prior_revision.revision = active_row.revision
              AND prior_revision.state = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'active pointer is corrupt';
        END IF;
        INSERT INTO domain.domain_version_revision
          (organization_id, domain_id, version, revision, state, reason_code, occurred_at, correlation_id)
          VALUES (p_organization_id, p_domain_id, active_row.version, active_row.revision + 1, 'SUPERSEDED', 'VERSION_SUPERSEDED', p_occurred_at, p_correlation_id);
        INSERT INTO domain.domain_evidence
          (organization_id, aggregate_id, version, state, revision, package_digest, report_digest, approval_evidence_digest, compatibility_digest, reason_code, occurred_at, record_digest)
          SELECT p_organization_id, p_domain_id, active_row.version, 'SUPERSEDED', active_row.revision + 1,
                 active_row.package_digest, prior.report_digest, prior.approval_evidence_digest,
                 p_compatibility_digest, 'VERSION_SUPERSEDED', p_occurred_at, p_prior_evidence_record_digest
          FROM domain.domain_evidence AS prior
          WHERE prior.organization_id = p_organization_id
            AND prior.aggregate_id = p_domain_id
            AND prior.version = active_row.version
            AND prior.report_digest IS NOT NULL
            AND prior.approval_evidence_digest IS NOT NULL
          ORDER BY prior.revision DESC LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'prior-version evidence missing';
        END IF;
        INSERT INTO domain.domain_event_outbox
          (organization_id, event_id, aggregate_id, aggregate_version, event_type, resource_digest, evidence_digest, reason_code, correlation_id, causation_id, occurred_at, event_digest)
          VALUES (p_organization_id, p_prior_event_id, p_domain_id, active_row.revision + 1, 'domain.version.superseded.v1', active_row.package_digest, p_prior_evidence_record_digest, 'VERSION_SUPERSEDED', p_correlation_id, NULL, p_occurred_at, p_prior_event_digest);
    END IF;
    INSERT INTO domain.domain_version_revision
      (organization_id, domain_id, version, revision, state, reason_code, occurred_at, correlation_id)
      VALUES (p_organization_id, p_domain_id, p_version, p_expected_revision + 1, 'ACTIVE', 'VERSION_ACTIVATED', p_occurred_at, p_correlation_id);
    INSERT INTO domain.domain_evidence
      (organization_id, aggregate_id, version, state, revision, package_digest, report_digest, approval_evidence_digest, compatibility_digest, reason_code, occurred_at, record_digest)
      VALUES (p_organization_id, p_domain_id, p_version, 'ACTIVE', p_expected_revision + 1, p_package_digest, p_report_digest, p_approval_evidence_digest, p_compatibility_digest, 'VERSION_ACTIVATED', p_occurred_at, p_evidence_record_digest);
    INSERT INTO domain.domain_event_outbox
      (organization_id, event_id, aggregate_id, aggregate_version, event_type, resource_digest, evidence_digest, reason_code, correlation_id, causation_id, occurred_at, event_digest)
      VALUES (p_organization_id, p_event_id, p_domain_id, p_expected_revision + 1, 'domain.version.activated.v1', p_package_digest, p_evidence_record_digest, 'VERSION_ACTIVATED', p_correlation_id, NULL, p_occurred_at, p_event_digest);
    INSERT INTO domain.active_domain_pointer
      (organization_id, domain_id, version, package_digest, revision, activated_at)
      VALUES (p_organization_id, p_domain_id, p_version, p_package_digest, p_expected_revision + 1, p_occurred_at)
      ON CONFLICT (organization_id, domain_id) DO UPDATE
      SET version = EXCLUDED.version,
          package_digest = EXCLUDED.package_digest,
          revision = EXCLUDED.revision,
          activated_at = EXCLUDED.activated_at;
    INSERT INTO domain.domain_idempotency
      (organization_id, idempotency_key, request_digest, response_digest, created_at)
      VALUES (p_organization_id, p_idempotency_key, p_request_digest, p_response_digest, p_occurred_at);
END;
$$;

REVOKE ALL ON FUNCTION domain.activate_domain_version(uuid, text, text, bigint, text, text, text, text, text, text, text, uuid, uuid, text, text, uuid, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION domain.activate_domain_version(uuid, text, text, bigint, text, text, text, text, text, text, text, uuid, uuid, text, text, uuid, text, text, timestamptz) TO planeon_kn_domain_runtime;

GRANT SELECT, INSERT ON domain.domain_definition, domain.domain_version,
    domain.domain_version_revision, domain.semantic_mapping,
    domain.semantic_mapping_revision, domain.validation_report,
    domain.domain_evidence, domain.domain_event_outbox,
    domain.domain_idempotency TO planeon_kn_domain_runtime;
GRANT SELECT ON domain.active_domain_pointer TO planeon_kn_domain_runtime;

RESET ROLE;
COMMIT;
