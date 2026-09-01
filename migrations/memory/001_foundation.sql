BEGIN;

CREATE ROLE planeon_kn_memory_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE planeon_kn_memory_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE SCHEMA memory AUTHORIZATION planeon_kn_memory_owner;
REVOKE ALL ON SCHEMA public FROM planeon_kn_memory_owner, planeon_kn_memory_runtime;
GRANT USAGE ON SCHEMA memory TO planeon_kn_memory_runtime;

SET LOCAL ROLE planeon_kn_memory_owner;

CREATE TABLE memory.source_reference (
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
CREATE TABLE memory.inbox_event (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    PRIMARY KEY (organization_id, event_id)
);
CREATE TABLE memory.outbox_event (
    organization_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    PRIMARY KEY (organization_id, event_id)
);

ALTER TABLE memory.source_reference ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.source_reference FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.inbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.inbox_event FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.outbox_event FORCE ROW LEVEL SECURITY;

CREATE POLICY memory_source_tenant ON memory.source_reference USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY memory_inbox_tenant ON memory.inbox_event USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);
CREATE POLICY memory_outbox_tenant ON memory.outbox_event USING (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('planeon.organization_id', true), '')::uuid);

CREATE FUNCTION memory.set_tenant_context(value uuid) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN PERFORM set_config('planeon.organization_id', value::text, true); END $$;
CREATE FUNCTION memory.reject_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN RAISE EXCEPTION 'append-only table'; END $$;
CREATE TRIGGER source_reference_append_only BEFORE UPDATE OR DELETE ON memory.source_reference FOR EACH ROW EXECUTE FUNCTION memory.reject_mutation();
CREATE TRIGGER inbox_event_append_only BEFORE UPDATE OR DELETE ON memory.inbox_event FOR EACH ROW EXECUTE FUNCTION memory.reject_mutation();
CREATE TRIGGER outbox_event_append_only BEFORE UPDATE OR DELETE ON memory.outbox_event FOR EACH ROW EXECUTE FUNCTION memory.reject_mutation();

GRANT SELECT, INSERT ON memory.source_reference, memory.inbox_event, memory.outbox_event TO planeon_kn_memory_runtime;
REVOKE ALL ON FUNCTION memory.set_tenant_context(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.set_tenant_context(uuid) TO planeon_kn_memory_runtime;
RESET ROLE;
COMMIT;
