-- A logical charge survives placement loss and acknowledged mirror retirement.
-- Deletion retains the object until its charge is settled in the same transaction.
-- Only fresh registry publication placeholders and standalone mirror objects
-- adopt this ledger. Existing inventory, cache and OCI accounting is not guessed.
ALTER TABLE surface_objects ADD COLUMN accounting_origin_version BIGINT
  CHECK(accounting_origin_version IS NULL OR
    (accounting_origin_version = 7 AND registry_id IS NOT NULL AND cache_id IS NULL));

ALTER TABLE object_placements ADD COLUMN observed_placement_resource_version BIGINT
  CHECK(observed_placement_resource_version IS NULL OR observed_placement_resource_version > 0);
ALTER TABLE object_placements ADD COLUMN observed_write_spec_version BIGINT
  CHECK(observed_write_spec_version IS NULL OR observed_write_spec_version > 0);
ALTER TABLE object_placements ADD COLUMN observed_binding_resource_version BIGINT
  CHECK(observed_binding_resource_version IS NULL OR observed_binding_resource_version > 0);

-- Nonversioned providers retain their exact guarded Direct receipt provenance.
ALTER TABLE object_placements ADD COLUMN direct_upload_session_id KEYTEXT64
  REFERENCES direct_upload_sessions(session_id) ON DELETE RESTRICT;

-- Earlier terminal rows recorded provider progress without logical publication.
ALTER TABLE mirror_import_objects ADD COLUMN publication_commit_version BIGINT
  CHECK(publication_commit_version IS NULL OR (publication_commit_version = 7 AND state = 'committed'));

CREATE TABLE surface_object_usage (
  surface_object_id INTEGER PRIMARY KEY REFERENCES surface_objects(id) ON DELETE RESTRICT,
  org_id INTEGER REFERENCES orgs(id) ON DELETE RESTRICT,
  accounted_bytes BIGINT NOT NULL,
  resource_version BIGINT NOT NULL DEFAULT 1,
  updated_at BIGINT NOT NULL,
  CHECK(accounted_bytes >= 0),
  CHECK(resource_version > 0),
  CHECK(updated_at > 0)
);

-- Provider authority cannot return to a deleted binding's former stable identity.
-- These reservations deliberately outlive the bindings and their dependants.
CREATE TABLE binding_identity_reservations (
  stable_id KEYTEXT64 PRIMARY KEY,
  reservation_id KEYTEXT64 NOT NULL UNIQUE,
  reserved_at BIGINT NOT NULL,
  CHECK(length(stable_id) BETWEEN 1 AND 64),
  CHECK(length(reservation_id) = 36),
  CHECK(reserved_at >= 0)
);
