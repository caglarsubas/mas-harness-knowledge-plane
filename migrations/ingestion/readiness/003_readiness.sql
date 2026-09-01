BEGIN;

SET LOCAL ROLE planeon_kn_ingestion_owner;

ALTER TABLE ingestion.staged_batch
    ADD COLUMN IF NOT EXISTS partition_token text;
ALTER TABLE ingestion.staged_batch
    ADD CONSTRAINT staged_batch_future_partition_required
    CHECK (partition_token IS NOT NULL) NOT VALID;

CREATE TABLE ingestion.readiness_policy_observation (
    organization_id uuid NOT NULL,
    policy_id text NOT NULL,
    policy_version text NOT NULL,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    tenant_approval_digest text NOT NULL CHECK (tenant_approval_digest ~ '^sha256:[0-9a-f]{64}$'),
    effective_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > effective_at),
    threshold_digest text NOT NULL CHECK (threshold_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, policy_id, policy_version),
    UNIQUE (organization_id, policy_digest)
);

CREATE TABLE ingestion.measurement_observation (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    material_digest text NOT NULL CHECK (material_digest ~ '^sha256:[0-9a-f]{64}$'),
    record_set_digest text NOT NULL CHECK (record_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    checkpoint_candidate_digest text NOT NULL CHECK (checkpoint_candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
    partition_token text NOT NULL,
    expected_count integer NOT NULL CHECK (expected_count BETWEEN 0 AND 10000),
    observed_count integer NOT NULL CHECK (observed_count BETWEEN 0 AND expected_count),
    nonnull_count integer NOT NULL CHECK (nonnull_count BETWEEN 0 AND observed_count),
    duplicate_count integer NOT NULL CHECK (duplicate_count BETWEEN 0 AND observed_count),
    classified_count integer NOT NULL CHECK (classified_count BETWEEN 0 AND observed_count),
    provenanced_count integer NOT NULL CHECK (provenanced_count BETWEEN 0 AND observed_count),
    latest_source_observation_at timestamptz,
    prerequisite_digest text NOT NULL CHECK (prerequisite_digest ~ '^sha256:[0-9a-f]{64}$'),
    collected_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > collected_at),
    observation_digest text NOT NULL CHECK (observation_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, batch_id, observation_digest),
    FOREIGN KEY (organization_id, batch_id) REFERENCES ingestion.staged_batch (organization_id, batch_id)
);

CREATE TABLE ingestion.readiness_work_revision (
    organization_id uuid NOT NULL,
    work_id uuid NOT NULL,
    source_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    observation_digest text NOT NULL CHECK (observation_digest ~ '^sha256:[0-9a-f]{64}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 3),
    fencing_token bigint NOT NULL CHECK (fencing_token >= 0),
    state text NOT NULL CHECK (state IN ('PENDING', 'CLAIMED', 'RETRY_SCHEDULED', 'SUCCEEDED', 'DEAD_LETTERED')),
    worker_id text,
    eligible_at timestamptz NOT NULL,
    claim_expires_at timestamptz,
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    work_digest text NOT NULL CHECK (work_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, work_id, revision),
    UNIQUE (organization_id, work_digest)
);

CREATE TABLE ingestion.readiness_work_pointer (
    organization_id uuid NOT NULL,
    work_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 3),
    fencing_token bigint NOT NULL CHECK (fencing_token >= 0),
    state text NOT NULL CHECK (state IN ('PENDING', 'CLAIMED', 'RETRY_SCHEDULED', 'SUCCEEDED', 'DEAD_LETTERED')),
    PRIMARY KEY (organization_id, work_id),
    FOREIGN KEY (organization_id, work_id, revision)
        REFERENCES ingestion.readiness_work_revision (organization_id, work_id, revision)
);

CREATE TABLE ingestion.readiness_finding (
    organization_id uuid NOT NULL,
    assessment_id text NOT NULL,
    finding_id text NOT NULL,
    metric_id text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('PASS', 'WARN', 'FAIL')),
    reason_code text NOT NULL,
    observed_value text,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    observation_digest text NOT NULL CHECK (observation_digest ~ '^sha256:[0-9a-f]{64}$'),
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    finding_digest text NOT NULL CHECK (finding_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, assessment_id, finding_id),
    UNIQUE (organization_id, finding_digest)
);

CREATE TABLE ingestion.readiness_assessment (
    organization_id uuid NOT NULL,
    assessment_id text NOT NULL,
    assessment_version text NOT NULL,
    source_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    observation_digest text NOT NULL CHECK (observation_digest ~ '^sha256:[0-9a-f]{64}$'),
    decision text NOT NULL CHECK (decision IN ('PASS', 'WARN', 'FAIL')),
    overall_status text NOT NULL CHECK (overall_status IN ('READY', 'BLOCKED')),
    gate_result_digest text NOT NULL CHECK (gate_result_digest ~ '^sha256:[0-9a-f]{64}$'),
    evaluated_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > evaluated_at),
    assessment_digest text NOT NULL CHECK (assessment_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, assessment_id),
    UNIQUE (organization_id, assessment_digest)
);

CREATE TABLE ingestion.provenance_graph (
    organization_id uuid NOT NULL,
    graph_id text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('ASSESSMENT', 'COMMIT')),
    node_count integer NOT NULL CHECK (node_count BETWEEN 1 AND 32),
    edge_count integer NOT NULL CHECK (edge_count BETWEEN 0 AND 64),
    node_set_digest text NOT NULL CHECK (node_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    edge_set_digest text NOT NULL CHECK (edge_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    graph_digest text NOT NULL CHECK (graph_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, graph_id),
    UNIQUE (organization_id, graph_digest)
);

CREATE TABLE ingestion.readiness_evidence (
    organization_id uuid NOT NULL,
    evidence_id text NOT NULL,
    evidence_version text NOT NULL,
    record_state text NOT NULL CHECK (record_state = 'VERIFIED'),
    axis text NOT NULL CHECK (axis = 'SOURCE'),
    result text NOT NULL CHECK (result IN ('PASS', 'WARN', 'FAIL')),
    subject_id text NOT NULL,
    subject_digest text NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    provenance_digest text NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
    collected_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > collected_at),
    control_set_digest text NOT NULL CHECK (control_set_digest ~ '^sha256:[0-9a-f]{64}$'),
    record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, evidence_id),
    UNIQUE (organization_id, record_digest)
);

CREATE TABLE ingestion.source_readiness_revision (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('READY_FOR_APPROVAL', 'ACTIVE', 'DEGRADED', 'REVOKED')),
    batch_id uuid,
    assessment_id text,
    assessment_digest text CHECK (assessment_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_id text,
    evidence_record_digest text CHECK (evidence_record_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_digest text CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL,
    valid_until timestamptz,
    correlation_id uuid NOT NULL,
    PRIMARY KEY (organization_id, source_id, revision)
);

CREATE TABLE ingestion.source_readiness_pointer (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL CHECK (state IN ('READY_FOR_APPROVAL', 'ACTIVE', 'DEGRADED', 'REVOKED')),
    PRIMARY KEY (organization_id, source_id),
    FOREIGN KEY (organization_id, source_id, revision)
        REFERENCES ingestion.source_readiness_revision (organization_id, source_id, revision)
);

CREATE TABLE ingestion.batch_commit (
    organization_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    partition_token text NOT NULL,
    assessment_digest text NOT NULL CHECK (assessment_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_record_digest text NOT NULL CHECK (evidence_record_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    provenance_digest text NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
    approval_digest text NOT NULL CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
    checkpoint_digest text NOT NULL CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    committed_at timestamptz NOT NULL,
    commit_digest text NOT NULL CHECK (commit_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, batch_id),
    UNIQUE (organization_id, commit_digest)
);

CREATE TABLE ingestion.checkpoint_revision (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    partition_token text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    batch_id uuid NOT NULL,
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    checkpoint_digest text NOT NULL CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    batch_staged_at timestamptz NOT NULL,
    activated_at timestamptz NOT NULL CHECK (activated_at >= batch_staged_at),
    PRIMARY KEY (organization_id, source_id, partition_token, revision)
);

CREATE TABLE ingestion.checkpoint_pointer (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    partition_token text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    batch_staged_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, source_id, partition_token),
    FOREIGN KEY (organization_id, source_id, partition_token, revision)
        REFERENCES ingestion.checkpoint_revision (organization_id, source_id, partition_token, revision)
);

CREATE TABLE ingestion.dead_letter_record (
    organization_id uuid NOT NULL,
    dead_letter_id uuid NOT NULL,
    work_id uuid NOT NULL,
    source_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    batch_digest text NOT NULL CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    reason_code text NOT NULL,
    dead_lettered_at timestamptz NOT NULL,
    record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, dead_letter_id),
    UNIQUE (organization_id, record_digest)
);

CREATE TABLE ingestion.dead_letter_review (
    organization_id uuid NOT NULL,
    review_id uuid NOT NULL,
    dead_letter_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision = 'ACKNOWLEDGED'),
    reason_code text NOT NULL,
    reviewer_subject_id text NOT NULL,
    reviewed_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    review_digest text NOT NULL CHECK (review_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, review_id),
    UNIQUE (organization_id, review_digest),
    FOREIGN KEY (organization_id, dead_letter_id)
        REFERENCES ingestion.dead_letter_record (organization_id, dead_letter_id)
);

CREATE TABLE ingestion.readiness_event_outbox (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    source_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    event_type text NOT NULL CHECK (event_type IN (
        'data.readiness.pass.v1', 'data.readiness.warn.v1', 'data.readiness.fail.v1',
        'data.readiness.dead-lettered.v1', 'data.batch.committed.v1',
        'data.source.activated.v1', 'data.source.revoked.v1'
    )),
    batch_digest text CHECK (batch_digest ~ '^sha256:[0-9a-f]{64}$'),
    assessment_digest text CHECK (assessment_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_record_digest text CHECK (evidence_record_digest ~ '^sha256:[0-9a-f]{64}$'),
    reason_code text NOT NULL,
    correlation_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id, event_id),
    UNIQUE (organization_id, event_digest)
);

DO $planeon_readiness_rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'readiness_policy_observation', 'measurement_observation',
        'readiness_work_revision', 'readiness_work_pointer', 'readiness_finding',
        'readiness_assessment', 'provenance_graph', 'readiness_evidence',
        'source_readiness_revision', 'source_readiness_pointer', 'batch_commit',
        'checkpoint_revision', 'checkpoint_pointer', 'dead_letter_record',
        'dead_letter_review', 'readiness_event_outbox'
    ] LOOP
        EXECUTE format('ALTER TABLE ingestion.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE ingestion.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON ingestion.%I USING (organization_id = NULLIF(current_setting(''planeon.organization_id'', true), '''')::uuid) WITH CHECK (organization_id = NULLIF(current_setting(''planeon.organization_id'', true), '''')::uuid)',
            'tenant_' || table_name, table_name
        );
    END LOOP;
END
$planeon_readiness_rls$;

DO $planeon_readiness_append_only$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'readiness_policy_observation', 'measurement_observation',
        'readiness_work_revision', 'readiness_finding', 'readiness_assessment',
        'provenance_graph', 'readiness_evidence', 'source_readiness_revision',
        'batch_commit', 'checkpoint_revision', 'dead_letter_record',
        'dead_letter_review', 'readiness_event_outbox'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON ingestion.%I FOR EACH ROW EXECUTE FUNCTION ingestion.reject_mutation()',
            table_name || '_append_only', table_name
        );
    END LOOP;
END
$planeon_readiness_append_only$;

CREATE FUNCTION ingestion.compare_and_append_readiness_work(
    tenant_id uuid,
    expected_revision bigint,
    candidate ingestion.readiness_work_revision
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE current_pointer ingestion.readiness_work_pointer%ROWTYPE;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid OR
       candidate.organization_id <> tenant_id THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    SELECT * INTO current_pointer FROM ingestion.readiness_work_pointer
     WHERE organization_id = tenant_id AND work_id = candidate.work_id FOR UPDATE;
    IF expected_revision = 0 THEN
        IF FOUND OR candidate.revision <> 1 OR candidate.attempt <> 0 OR
           candidate.fencing_token <> 0 OR candidate.state <> 'PENDING' THEN
            RAISE EXCEPTION 'invalid initial work revision';
        END IF;
    ELSE
        IF NOT FOUND OR current_pointer.revision <> expected_revision OR
           candidate.revision <> expected_revision + 1 OR
           candidate.fencing_token < current_pointer.fencing_token OR
           current_pointer.state IN ('SUCCEEDED', 'DEAD_LETTERED') THEN
            RAISE EXCEPTION 'stale work revision';
        END IF;
        IF candidate.state = 'CLAIMED' AND
           (candidate.fencing_token <> current_pointer.fencing_token + 1 OR
            candidate.attempt <> current_pointer.attempt + 1 OR
            candidate.claim_expires_at <= candidate.occurred_at OR
            candidate.claim_expires_at > candidate.occurred_at + interval '300 seconds') THEN
            RAISE EXCEPTION 'invalid work claim fence';
        END IF;
    END IF;
    INSERT INTO ingestion.readiness_work_revision SELECT candidate.*;
    INSERT INTO ingestion.readiness_work_pointer VALUES (
        tenant_id, candidate.work_id, candidate.revision, candidate.attempt,
        candidate.fencing_token, candidate.state
    ) ON CONFLICT (organization_id, work_id) DO UPDATE SET
        revision = EXCLUDED.revision,
        attempt = EXCLUDED.attempt,
        fencing_token = EXCLUDED.fencing_token,
        state = EXCLUDED.state;
END
$planeon_function$;

CREATE FUNCTION ingestion.compare_and_append_source_readiness(
    tenant_id uuid,
    expected_revision bigint,
    candidate ingestion.source_readiness_revision
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE current_pointer ingestion.source_readiness_pointer%ROWTYPE;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid OR
       candidate.organization_id <> tenant_id THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    SELECT * INTO current_pointer FROM ingestion.source_readiness_pointer
     WHERE organization_id = tenant_id AND source_id = candidate.source_id FOR UPDATE;
    IF expected_revision = 0 THEN
        IF FOUND OR candidate.revision <> 1 THEN
            RAISE EXCEPTION 'invalid initial readiness revision';
        END IF;
    ELSE
        IF NOT FOUND OR current_pointer.revision <> expected_revision OR
           candidate.revision <> expected_revision + 1 THEN
            RAISE EXCEPTION 'stale readiness revision';
        END IF;
        IF current_pointer.state = 'REVOKED' THEN
            RAISE EXCEPTION 'revoked source cannot be re-enabled';
        END IF;
    END IF;
    INSERT INTO ingestion.source_readiness_revision SELECT candidate.*;
    INSERT INTO ingestion.source_readiness_pointer VALUES (
        tenant_id, candidate.source_id, candidate.revision, candidate.state
    ) ON CONFLICT (organization_id, source_id) DO UPDATE SET
        revision = EXCLUDED.revision,
        state = EXCLUDED.state;
END
$planeon_function$;

CREATE FUNCTION ingestion.compare_and_append_checkpoint(
    tenant_id uuid,
    expected_revision bigint,
    candidate ingestion.checkpoint_revision
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE current_pointer ingestion.checkpoint_pointer%ROWTYPE;
DECLARE bound_partition text;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid OR
       candidate.organization_id <> tenant_id THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    SELECT partition_token INTO bound_partition FROM ingestion.staged_batch
     WHERE organization_id = tenant_id AND batch_id = candidate.batch_id FOR UPDATE;
    IF NOT FOUND OR bound_partition IS NULL OR bound_partition <> candidate.partition_token THEN
        RAISE EXCEPTION 'batch partition is unbound';
    END IF;
    SELECT * INTO current_pointer FROM ingestion.checkpoint_pointer
     WHERE organization_id = tenant_id AND source_id = candidate.source_id
       AND partition_token = candidate.partition_token FOR UPDATE;
    IF expected_revision = 0 THEN
        IF FOUND OR candidate.revision <> 1 THEN
            RAISE EXCEPTION 'invalid initial checkpoint revision';
        END IF;
    ELSE
        IF NOT FOUND OR current_pointer.revision <> expected_revision OR
           candidate.revision <> expected_revision + 1 OR
           candidate.fencing_token <= current_pointer.fencing_token OR
           candidate.batch_staged_at <= current_pointer.batch_staged_at THEN
            RAISE EXCEPTION 'checkpoint order invalid';
        END IF;
    END IF;
    INSERT INTO ingestion.checkpoint_revision SELECT candidate.*;
    INSERT INTO ingestion.checkpoint_pointer VALUES (
        tenant_id, candidate.source_id, candidate.partition_token,
        candidate.revision, candidate.fencing_token, candidate.batch_staged_at
    ) ON CONFLICT (organization_id, source_id, partition_token) DO UPDATE SET
        revision = EXCLUDED.revision,
        fencing_token = EXCLUDED.fencing_token,
        batch_staged_at = EXCLUDED.batch_staged_at;
END
$planeon_function$;

CREATE FUNCTION ingestion.commit_readiness_batch(
    tenant_id uuid,
    expected_readiness_revision bigint,
    expected_checkpoint_revision bigint,
    approval_verified boolean,
    approval_expires_at timestamptz,
    candidate_commit ingestion.batch_commit,
    candidate_checkpoint ingestion.checkpoint_revision,
    candidate_readiness ingestion.source_readiness_revision,
    candidate_graph ingestion.provenance_graph,
    candidate_evidence ingestion.readiness_evidence,
    candidate_events ingestion.readiness_event_outbox[]
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ingestion
AS $planeon_function$
DECLARE staged ingestion.staged_batch%ROWTYPE;
DECLARE current_readiness ingestion.source_readiness_pointer%ROWTYPE;
DECLARE assessment ingestion.readiness_assessment%ROWTYPE;
DECLARE current_checkpoint ingestion.checkpoint_pointer%ROWTYPE;
DECLARE candidate_event ingestion.readiness_event_outbox;
BEGIN
    IF tenant_id IS DISTINCT FROM NULLIF(current_setting('planeon.organization_id', true), '')::uuid OR
       candidate_commit.organization_id <> tenant_id OR
       candidate_checkpoint.organization_id <> tenant_id OR
       candidate_readiness.organization_id <> tenant_id OR
       candidate_graph.organization_id <> tenant_id OR
       candidate_evidence.organization_id <> tenant_id THEN
        RAISE EXCEPTION 'tenant context mismatch';
    END IF;
    IF approval_verified IS DISTINCT FROM true OR approval_expires_at <= candidate_commit.committed_at THEN
        RAISE EXCEPTION 'owner approval is stale or unverified';
    END IF;
    SELECT * INTO STRICT staged FROM ingestion.staged_batch
     WHERE organization_id = tenant_id AND batch_id = candidate_commit.batch_id FOR UPDATE;
    IF staged.partition_token IS NULL OR
       (staged.source_id, staged.source_version_digest, staged.batch_digest,
        staged.partition_token, staged.fencing_token) IS DISTINCT FROM
       (candidate_commit.source_id, candidate_commit.source_version_digest,
        candidate_commit.batch_digest, candidate_commit.partition_token,
        candidate_commit.fencing_token) THEN
        RAISE EXCEPTION 'committed batch scope mismatch or partition unbound';
    END IF;
    SELECT * INTO STRICT current_readiness FROM ingestion.source_readiness_pointer
     WHERE organization_id = tenant_id AND source_id = candidate_commit.source_id FOR UPDATE;
    IF current_readiness.revision <> expected_readiness_revision OR
       current_readiness.state <> 'READY_FOR_APPROVAL' OR
       candidate_readiness.revision <> expected_readiness_revision + 1 OR
       candidate_readiness.state <> 'ACTIVE' OR
       candidate_readiness.batch_id <> candidate_commit.batch_id OR
       candidate_readiness.valid_until <= candidate_commit.committed_at THEN
        RAISE EXCEPTION 'source is not current ready for approval';
    END IF;
    SELECT * INTO STRICT assessment FROM ingestion.readiness_assessment
     WHERE organization_id = tenant_id
       AND assessment_id = candidate_readiness.assessment_id FOR UPDATE;
    IF assessment.decision <> 'PASS' OR assessment.overall_status <> 'READY' OR
       assessment.valid_until <= candidate_commit.committed_at OR
       assessment.assessment_digest <> candidate_commit.assessment_digest OR
       assessment.assessment_digest <> candidate_readiness.assessment_digest OR
       assessment.policy_digest <> candidate_commit.policy_digest OR
       assessment.policy_digest <> candidate_readiness.policy_digest THEN
        RAISE EXCEPTION 'readiness assessment is stale or mismatched';
    END IF;
    IF candidate_graph.purpose <> 'COMMIT' OR
       candidate_graph.graph_digest <> candidate_commit.provenance_digest OR
       candidate_evidence.record_state <> 'VERIFIED' OR
       candidate_evidence.axis <> 'SOURCE' OR candidate_evidence.result <> 'PASS' OR
       candidate_evidence.valid_until <= candidate_commit.committed_at OR
       candidate_evidence.provenance_digest <> candidate_graph.graph_digest OR
       candidate_evidence.record_digest <> candidate_commit.evidence_record_digest OR
       candidate_readiness.evidence_record_digest <> candidate_evidence.record_digest THEN
        RAISE EXCEPTION 'commit evidence is stale or mismatched';
    END IF;
    IF (candidate_checkpoint.source_id, candidate_checkpoint.source_version_digest,
        candidate_checkpoint.partition_token, candidate_checkpoint.batch_id,
        candidate_checkpoint.batch_digest, candidate_checkpoint.checkpoint_digest,
        candidate_checkpoint.fencing_token, candidate_checkpoint.batch_staged_at) IS DISTINCT FROM
       (candidate_commit.source_id, candidate_commit.source_version_digest,
        candidate_commit.partition_token, candidate_commit.batch_id,
        candidate_commit.batch_digest, candidate_commit.checkpoint_digest,
        candidate_commit.fencing_token, staged.staged_at) THEN
        RAISE EXCEPTION 'checkpoint candidate scope mismatch';
    END IF;
    SELECT * INTO current_checkpoint FROM ingestion.checkpoint_pointer
     WHERE organization_id = tenant_id AND source_id = candidate_commit.source_id
       AND partition_token = candidate_commit.partition_token FOR UPDATE;
    IF expected_checkpoint_revision = 0 THEN
        IF FOUND OR candidate_checkpoint.revision <> 1 THEN
            RAISE EXCEPTION 'invalid initial checkpoint revision';
        END IF;
    ELSE
        IF NOT FOUND OR current_checkpoint.revision <> expected_checkpoint_revision OR
           candidate_checkpoint.revision <> expected_checkpoint_revision + 1 OR
           candidate_checkpoint.fencing_token <= current_checkpoint.fencing_token OR
           candidate_checkpoint.batch_staged_at <= current_checkpoint.batch_staged_at THEN
            RAISE EXCEPTION 'checkpoint order invalid';
        END IF;
    END IF;
    IF cardinality(candidate_events) <> 2 THEN
        RAISE EXCEPTION 'commit requires exact batch and source events';
    END IF;
    INSERT INTO ingestion.provenance_graph SELECT candidate_graph.*;
    INSERT INTO ingestion.readiness_evidence SELECT candidate_evidence.*;
    INSERT INTO ingestion.batch_commit SELECT candidate_commit.*;
    INSERT INTO ingestion.checkpoint_revision SELECT candidate_checkpoint.*;
    INSERT INTO ingestion.checkpoint_pointer VALUES (
        tenant_id, candidate_checkpoint.source_id, candidate_checkpoint.partition_token,
        candidate_checkpoint.revision, candidate_checkpoint.fencing_token,
        candidate_checkpoint.batch_staged_at
    ) ON CONFLICT (organization_id, source_id, partition_token) DO UPDATE SET
        revision = EXCLUDED.revision,
        fencing_token = EXCLUDED.fencing_token,
        batch_staged_at = EXCLUDED.batch_staged_at;
    INSERT INTO ingestion.source_readiness_revision SELECT candidate_readiness.*;
    INSERT INTO ingestion.source_readiness_pointer VALUES (
        tenant_id, candidate_readiness.source_id, candidate_readiness.revision,
        candidate_readiness.state
    ) ON CONFLICT (organization_id, source_id) DO UPDATE SET
        revision = EXCLUDED.revision,
        state = EXCLUDED.state;
    FOREACH candidate_event IN ARRAY candidate_events LOOP
        IF candidate_event.organization_id <> tenant_id OR
           candidate_event.source_id <> candidate_commit.source_id OR
           candidate_event.event_type NOT IN ('data.batch.committed.v1', 'data.source.activated.v1') THEN
            RAISE EXCEPTION 'commit event scope mismatch';
        END IF;
        INSERT INTO ingestion.readiness_event_outbox SELECT candidate_event.*;
    END LOOP;
END
$planeon_function$;

GRANT SELECT, INSERT ON
    ingestion.readiness_policy_observation,
    ingestion.measurement_observation,
    ingestion.readiness_work_revision,
    ingestion.readiness_finding,
    ingestion.readiness_assessment,
    ingestion.provenance_graph,
    ingestion.readiness_evidence,
    ingestion.source_readiness_revision,
    ingestion.batch_commit,
    ingestion.checkpoint_revision,
    ingestion.dead_letter_record,
    ingestion.dead_letter_review,
    ingestion.readiness_event_outbox
TO planeon_kn_ingestion_runtime;
GRANT SELECT ON
    ingestion.readiness_work_pointer,
    ingestion.source_readiness_pointer,
    ingestion.checkpoint_pointer
TO planeon_kn_ingestion_runtime;

REVOKE ALL ON FUNCTION ingestion.compare_and_append_readiness_work(uuid, bigint, ingestion.readiness_work_revision) FROM PUBLIC;
REVOKE ALL ON FUNCTION ingestion.compare_and_append_source_readiness(uuid, bigint, ingestion.source_readiness_revision) FROM PUBLIC;
REVOKE ALL ON FUNCTION ingestion.compare_and_append_checkpoint(uuid, bigint, ingestion.checkpoint_revision) FROM PUBLIC;
REVOKE ALL ON FUNCTION ingestion.commit_readiness_batch(uuid, bigint, bigint, boolean, timestamptz, ingestion.batch_commit, ingestion.checkpoint_revision, ingestion.source_readiness_revision, ingestion.provenance_graph, ingestion.readiness_evidence, ingestion.readiness_event_outbox[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingestion.compare_and_append_readiness_work(uuid, bigint, ingestion.readiness_work_revision) TO planeon_kn_ingestion_runtime;
GRANT EXECUTE ON FUNCTION ingestion.compare_and_append_source_readiness(uuid, bigint, ingestion.source_readiness_revision) TO planeon_kn_ingestion_runtime;
GRANT EXECUTE ON FUNCTION ingestion.compare_and_append_checkpoint(uuid, bigint, ingestion.checkpoint_revision) TO planeon_kn_ingestion_runtime;
GRANT EXECUTE ON FUNCTION ingestion.commit_readiness_batch(uuid, bigint, bigint, boolean, timestamptz, ingestion.batch_commit, ingestion.checkpoint_revision, ingestion.source_readiness_revision, ingestion.provenance_graph, ingestion.readiness_evidence, ingestion.readiness_event_outbox[]) TO planeon_kn_ingestion_runtime;

RESET ROLE;
COMMIT;
