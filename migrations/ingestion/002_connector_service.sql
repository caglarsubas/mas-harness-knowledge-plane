BEGIN;

SET LOCAL ROLE planeon_kn_ingestion_owner;

CREATE TABLE ingestion.source_definition (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    connector_kind text NOT NULL CHECK (connector_kind IN ('FILE', 'HTTP', 'POSTGRESQL', 'EVENT')),
    profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
    endpoint_ref_digest text NOT NULL CHECK (endpoint_ref_digest ~ '^sha256:[0-9a-f]{64}$'),
    credential_ref_digest text CHECK (credential_ref_digest ~ '^sha256:[0-9a-f]{64}$'),
    network_policy_digest text NOT NULL CHECK (network_policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_schema_digest text NOT NULL CHECK (expected_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    active_domain_version_digest text NOT NULL CHECK (active_domain_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    semantic_mapping_digest text NOT NULL CHECK (semantic_mapping_digest ~ '^sha256:[0-9a-f]{64}$'),
    owner_digest text NOT NULL CHECK (owner_digest ~ '^sha256:[0-9a-f]{64}$'),
    classification text NOT NULL CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    residency_tokens text[] NOT NULL CHECK (cardinality(residency_tokens) BETWEEN 1 AND 32),
    max_records integer NOT NULL CHECK (max_records BETWEEN 1 AND 10000),
    max_bytes integer NOT NULL CHECK (max_bytes BETWEEN 1 AND 8388608),
    deadline_ms integer NOT NULL CHECK (deadline_ms BETWEEN 1 AND 30000),
    created_at timestamptz NOT NULL,
    created_by_subject_id text NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, source_id),
    UNIQUE (organization_id, source_id, source_version_digest)
);

CREATE TABLE ingestion.source_revision (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('DECLARED', 'VALIDATING', 'VALID', 'INVALID', 'SAMPLING', 'SAMPLED', 'DISABLED')),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, source_id, revision),
    FOREIGN KEY (organization_id, source_id, source_version_digest)
        REFERENCES ingestion.source_definition (organization_id, source_id, source_version_digest)
);

CREATE TABLE ingestion.connector_lease_revision (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    partition_token text NOT NULL,
    lease_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    owner_worker_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('ACQUIRED', 'RENEWED', 'RELEASED', 'EXPIRED')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    reason_code text NOT NULL,
    correlation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, source_id, partition_token, revision),
    UNIQUE (organization_id, source_id, partition_token, lease_id, revision),
    FOREIGN KEY (organization_id, source_id, source_version_digest)
        REFERENCES ingestion.source_definition (organization_id, source_id, source_version_digest)
);

CREATE TABLE ingestion.connector_lease_pointer (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    partition_token text NOT NULL,
    lease_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    PRIMARY KEY (organization_id, source_id, partition_token),
    FOREIGN KEY (organization_id, source_id, partition_token, lease_id, revision)
        REFERENCES ingestion.connector_lease_revision (organization_id, source_id, partition_token, lease_id, revision)
);

CREATE TABLE ingestion.staged_batch (
    organization_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    expected_schema_digest text NOT NULL CHECK (expected_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    active_domain_version_digest text NOT NULL CHECK (active_domain_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    semantic_mapping_digest text NOT NULL CHECK (semantic_mapping_digest ~ '^sha256:[0-9a-f]{64}$'),
    material_digest text NOT NULL CHECK (material_digest ~ '^sha256:[0-9a-f]{64}$'),
    checkpoint_candidate_digest text NOT NULL CHECK (checkpoint_candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    media_type text NOT NULL,
    connector_kind text NOT NULL CHECK (connector_kind IN ('FILE', 'HTTP', 'POSTGRESQL', 'EVENT')),
    state text NOT NULL CHECK (state = 'STAGED'),
    record_count integer NOT NULL CHECK (record_count BETWEEN 1 AND 10000),
    byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 8388608),
    record_set_digest text NOT NULL CHECK (record_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    staged_at timestamptz NOT NULL,
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, batch_id),
    UNIQUE (organization_id, batch_digest),
    FOREIGN KEY (organization_id, source_id, source_version_digest)
        REFERENCES ingestion.source_definition (organization_id, source_id, source_version_digest)
);

CREATE TABLE ingestion.staged_record_digest (
    organization_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    schema_digest text NOT NULL CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    encoded_bytes integer NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 65536),
    PRIMARY KEY (organization_id, batch_id, ordinal),
    FOREIGN KEY (organization_id, batch_id)
        REFERENCES ingestion.staged_batch (organization_id, batch_id)
);

CREATE TABLE ingestion.ingestion_idempotency (
    organization_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    result_digest text NOT NULL CHECK (result_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, idempotency_key)
);

CREATE TABLE ingestion.ingestion_evidence (
    organization_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_state text NOT NULL CHECK (source_state IN ('DECLARED', 'VALID', 'INVALID', 'SAMPLED', 'DISABLED')),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    batch_digest text CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    endpoint_grant_digest text CHECK (endpoint_grant_digest ~ '^sha256:[0-9a-f]{64}$'),
    domain_observation_digest text CHECK (domain_observation_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, evidence_id),
    UNIQUE (organization_id, record_digest)
);

CREATE TABLE ingestion.ingestion_event_outbox (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    source_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'data.source.declared.v1', 'data.source.validated.v1',
        'data.source.invalid.v1', 'data.source.sample-staged.v1',
        'data.source.disabled.v1'
    )),
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    batch_digest text CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    correlation_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, event_id),
    UNIQUE (organization_id, event_digest)
);

DO $planeon_rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_definition', 'source_revision', 'connector_lease_revision',
        'connector_lease_pointer', 'staged_batch', 'staged_record_digest',
        'ingestion_idempotency', 'ingestion_evidence', 'ingestion_event_outbox'
    ] LOOP
        EXECUTE format('ALTER TABLE ingestion.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE ingestion.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON ingestion.%I USING (organization_id = NULLIF(current_setting(''planeon.organization_id'', true), '''')::uuid) WITH CHECK (organization_id = NULLIF(current_setting(''planeon.organization_id'', true), '''')::uuid)',
            'tenant_' || table_name, table_name
        );
    END LOOP;
END
$planeon_rls$;

DO $planeon_append_only$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_definition', 'source_revision', 'connector_lease_revision',
        'staged_batch', 'staged_record_digest', 'ingestion_idempotency',
        'ingestion_evidence', 'ingestion_event_outbox'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON ingestion.%I FOR EACH ROW EXECUTE FUNCTION ingestion.reject_mutation()',
            table_name || '_append_only', table_name
        );
    END LOOP;
END
$planeon_append_only$;

CREATE FUNCTION ingestion.compare_and_append_lease(
    tenant_id uuid,
    expected_revision bigint,
    candidate_source_id uuid,
    candidate_source_version_digest text,
    candidate_partition text,
    candidate_lease_id uuid,
    candidate_revision bigint,
    candidate_fencing_token bigint,
    candidate_owner_worker_id text,
    candidate_state text,
    candidate_issued_at timestamptz,
    candidate_expires_at timestamptz,
    candidate_reason_code text,
    candidate_correlation_id uuid
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE current_pointer ingestion.connector_lease_pointer%ROWTYPE;
DECLARE current_revision ingestion.connector_lease_revision%ROWTYPE;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    SELECT * INTO current_pointer
      FROM ingestion.connector_lease_pointer
     WHERE organization_id = tenant_id
       AND source_id = candidate_source_id
       AND partition_token = candidate_partition
     FOR UPDATE;
    IF expected_revision = 0 THEN
        IF FOUND OR candidate_revision <> 1 OR candidate_fencing_token <> 1 OR candidate_state <> 'ACQUIRED' THEN
            RAISE EXCEPTION 'invalid initial lease revision';
        END IF;
    ELSE
        IF NOT FOUND OR current_pointer.revision <> expected_revision OR candidate_revision <> expected_revision + 1 THEN
            RAISE EXCEPTION 'stale lease revision';
        END IF;
        SELECT * INTO STRICT current_revision
          FROM ingestion.connector_lease_revision
         WHERE organization_id = tenant_id
           AND source_id = candidate_source_id
           AND partition_token = candidate_partition
           AND lease_id = current_pointer.lease_id
           AND revision = current_pointer.revision;
        IF candidate_source_version_digest <> current_revision.source_version_digest OR
           (candidate_state <> 'ACQUIRED' AND candidate_owner_worker_id <> current_revision.owner_worker_id) THEN
            RAISE EXCEPTION 'lease scope mismatch';
        END IF;
        IF candidate_state IN ('RENEWED', 'RELEASED', 'EXPIRED') AND
           (candidate_lease_id <> current_pointer.lease_id OR candidate_fencing_token <> current_pointer.fencing_token) THEN
            RAISE EXCEPTION 'lease fence mismatch';
        END IF;
        IF candidate_state IN ('RENEWED', 'RELEASED') AND
           (current_revision.state NOT IN ('ACQUIRED', 'RENEWED') OR current_revision.expires_at <= candidate_issued_at) THEN
            RAISE EXCEPTION 'lease is not current';
        END IF;
        IF candidate_state = 'ACQUIRED' AND current_revision.state IN ('ACQUIRED', 'RENEWED') AND
           current_revision.expires_at > candidate_issued_at THEN
            RAISE EXCEPTION 'lease is already held';
        END IF;
        IF candidate_state = 'ACQUIRED' AND
           (candidate_lease_id = current_pointer.lease_id OR candidate_fencing_token <= current_pointer.fencing_token) THEN
            RAISE EXCEPTION 'fencing token did not increase';
        END IF;
    END IF;
    IF candidate_state IN ('ACQUIRED', 'RENEWED') AND
       (candidate_expires_at <= candidate_issued_at OR
        candidate_expires_at > candidate_issued_at + interval '300 seconds') THEN
        RAISE EXCEPTION 'lease ttl is invalid';
    END IF;
    INSERT INTO ingestion.connector_lease_revision VALUES (
        tenant_id, candidate_source_id, candidate_source_version_digest,
        candidate_partition, candidate_lease_id, candidate_revision,
        candidate_fencing_token, candidate_owner_worker_id, candidate_state,
        candidate_issued_at, candidate_expires_at, candidate_reason_code,
        candidate_correlation_id
    );
    INSERT INTO ingestion.connector_lease_pointer VALUES (
        tenant_id, candidate_source_id, candidate_partition, candidate_lease_id,
        candidate_revision, candidate_fencing_token
    ) ON CONFLICT (organization_id, source_id, partition_token) DO UPDATE SET
        lease_id = EXCLUDED.lease_id,
        revision = EXCLUDED.revision,
        fencing_token = EXCLUDED.fencing_token;
END
$planeon_function$;

CREATE FUNCTION ingestion.stage_metadata(
    tenant_id uuid,
    expected_source_revision bigint,
    expected_partition text,
    expected_lease_revision bigint,
    expected_fencing_token bigint,
    candidate_batch ingestion.staged_batch,
    record_digests text[],
    schema_digests text[],
    encoded_sizes integer[]
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE current_source_revision bigint;
DECLARE current_source_state text;
DECLARE current_lease ingestion.connector_lease_pointer%ROWTYPE;
DECLARE current_lease_state text;
DECLARE current_lease_expires_at timestamptz;
DECLARE current_lease_source_version_digest text;
DECLARE item_count integer;
DECLARE ordinal_index integer;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid OR
       candidate_batch.organization_id <> tenant_id THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    SELECT revision, state INTO current_source_revision, current_source_state
      FROM ingestion.source_revision
     WHERE organization_id = tenant_id AND source_id = candidate_batch.source_id
     ORDER BY revision DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND OR current_source_revision <> expected_source_revision OR current_source_state <> 'VALID' THEN
        RAISE EXCEPTION 'stale source revision';
    END IF;
    SELECT pointer, revision.state, revision.expires_at, revision.source_version_digest
      INTO current_lease, current_lease_state, current_lease_expires_at, current_lease_source_version_digest
      FROM ingestion.connector_lease_pointer AS pointer
      JOIN ingestion.connector_lease_revision AS revision
        ON revision.organization_id = pointer.organization_id
       AND revision.source_id = pointer.source_id
       AND revision.partition_token = pointer.partition_token
       AND revision.lease_id = pointer.lease_id
       AND revision.revision = pointer.revision
     WHERE pointer.organization_id = tenant_id
       AND pointer.source_id = candidate_batch.source_id
       AND pointer.partition_token = expected_partition
     FOR UPDATE OF pointer;
    IF NOT FOUND OR current_lease.revision <> expected_lease_revision OR
       current_lease.fencing_token <> expected_fencing_token OR
       candidate_batch.fencing_token <> expected_fencing_token OR
       current_lease_state NOT IN ('ACQUIRED', 'RENEWED') OR
       current_lease_expires_at <= candidate_batch.staged_at OR
       current_lease_source_version_digest <> candidate_batch.source_version_digest THEN
        RAISE EXCEPTION 'lease fence mismatch';
    END IF;
    item_count := cardinality(record_digests);
    IF item_count IS NULL OR item_count <> candidate_batch.record_count OR
       cardinality(schema_digests) <> item_count OR cardinality(encoded_sizes) <> item_count THEN
        RAISE EXCEPTION 'record metadata mismatch';
    END IF;
    INSERT INTO ingestion.staged_batch SELECT candidate_batch.*;
    FOR ordinal_index IN 1..item_count LOOP
        INSERT INTO ingestion.staged_record_digest VALUES (
            tenant_id, candidate_batch.batch_id, ordinal_index - 1,
            record_digests[ordinal_index], schema_digests[ordinal_index],
            encoded_sizes[ordinal_index]
        );
    END LOOP;
END
$planeon_function$;

GRANT SELECT, INSERT ON
    ingestion.source_definition,
    ingestion.source_revision,
    ingestion.connector_lease_revision,
    ingestion.staged_batch,
    ingestion.staged_record_digest,
    ingestion.ingestion_idempotency,
    ingestion.ingestion_evidence,
    ingestion.ingestion_event_outbox
TO planeon_kn_ingestion_runtime;
GRANT SELECT ON ingestion.connector_lease_pointer TO planeon_kn_ingestion_runtime;

REVOKE ALL ON FUNCTION ingestion.compare_and_append_lease(uuid, bigint, uuid, text, text, uuid, bigint, bigint, text, text, timestamptz, timestamptz, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION ingestion.stage_metadata(uuid, bigint, text, bigint, bigint, ingestion.staged_batch, text[], text[], integer[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingestion.compare_and_append_lease(uuid, bigint, uuid, text, text, uuid, bigint, bigint, text, text, timestamptz, timestamptz, text, uuid) TO planeon_kn_ingestion_runtime;
GRANT EXECUTE ON FUNCTION ingestion.stage_metadata(uuid, bigint, text, bigint, bigint, ingestion.staged_batch, text[], text[], integer[]) TO planeon_kn_ingestion_runtime;

RESET ROLE;
COMMIT;
