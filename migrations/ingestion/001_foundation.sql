BEGIN;

CREATE ROLE planeon_kn_ingestion_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE planeon_kn_ingestion_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE SCHEMA ingestion AUTHORIZATION planeon_kn_ingestion_owner;
REVOKE ALL ON SCHEMA public FROM planeon_kn_ingestion_owner, planeon_kn_ingestion_runtime;
GRANT USAGE ON SCHEMA ingestion TO planeon_kn_ingestion_runtime;

SET LOCAL ROLE planeon_kn_ingestion_owner;

CREATE TABLE ingestion.source_reference (
    organization_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_version_digest text NOT NULL CHECK (source_version_digest ~ '^sha256:[0-9a-f]{64}$'),
    locator_digest text NOT NULL CHECK (locator_digest ~ '^sha256:[0-9a-f]{64}$'),
    content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 3 AND 129),
    content_bytes bigint NOT NULL CHECK (content_bytes >= 0),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (organization_id, source_id, source_version_digest)
);
CREATE TABLE ingestion.inbox_event (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    PRIMARY KEY (organization_id, event_id)
);
CREATE TABLE ingestion.outbox_event (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    PRIMARY KEY (organization_id, event_id)
);

ALTER TABLE ingestion.source_reference ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingestion.source_reference FORCE ROW LEVEL SECURITY;
ALTER TABLE ingestion.inbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingestion.inbox_event FORCE ROW LEVEL SECURITY;
ALTER TABLE ingestion.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingestion.outbox_event FORCE ROW LEVEL SECURITY;

CREATE POLICY ingestion_source_tenant ON ingestion.source_reference USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY ingestion_inbox_tenant ON ingestion.inbox_event USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY ingestion_outbox_tenant ON ingestion.outbox_event USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);

CREATE FUNCTION ingestion.set_tenant_context(value uuid) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN PERFORM set_config('planeon.organization_id', value::text, true); END $$;
CREATE FUNCTION ingestion.reject_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN RAISE EXCEPTION 'append-only table'; END $$;
CREATE TRIGGER source_reference_append_only BEFORE UPDATE OR DELETE ON ingestion.source_reference FOR EACH ROW EXECUTE FUNCTION ingestion.reject_mutation();
CREATE TRIGGER inbox_event_append_only BEFORE UPDATE OR DELETE ON ingestion.inbox_event FOR EACH ROW EXECUTE FUNCTION ingestion.reject_mutation();
CREATE TRIGGER outbox_event_append_only BEFORE UPDATE OR DELETE ON ingestion.outbox_event FOR EACH ROW EXECUTE FUNCTION ingestion.reject_mutation();

GRANT SELECT, INSERT ON ingestion.source_reference, ingestion.inbox_event, ingestion.outbox_event TO planeon_kn_ingestion_runtime;
REVOKE ALL ON FUNCTION ingestion.set_tenant_context(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingestion.set_tenant_context(uuid) TO planeon_kn_ingestion_runtime;
RESET ROLE;
COMMIT;
