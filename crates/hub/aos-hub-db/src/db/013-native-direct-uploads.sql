-- Native signed multipart state belongs to the main Hub database. This
-- journal stores provider upload identifiers and public object metadata only;
-- credentials, signed URLs and object bytes never enter state_json.
CREATE TABLE native_direct_uploads (
  session_id KEYTEXT64 NOT NULL PRIMARY KEY,
  deployment_id KEYTEXT255 NOT NULL,
  principal_id KEYTEXT255 NOT NULL,
  client_operation_id KEYTEXT64 NOT NULL,
  oci_upload_id KEYTEXT64,
  state KEYTEXT32 NOT NULL,
  source_sha256 KEYTEXT64 NOT NULL,
  declared_size BIGINT NOT NULL,
  verified_sha256 KEYTEXT64,
  verified_size BIGINT,
  materialization_placement_id INTEGER,
  materialization_binding_id INTEGER,
  state_json LONGTEXT NOT NULL,
  resource_version BIGINT NOT NULL,
  UNIQUE(deployment_id, principal_id, client_operation_id),
  UNIQUE(oci_upload_id),
  CHECK(state IN ('creating', 'uploading', 'completing', 'verified', 'committed',
                 'aborting', 'aborted', 'blocked_unknown')),
  CHECK(declared_size >= 0 AND declared_size <= 17179869184),
  CHECK(resource_version > 0),
  CHECK((verified_sha256 IS NULL AND verified_size IS NULL)
     OR (verified_sha256 IS NOT NULL AND verified_size IS NOT NULL
         AND verified_sha256 = source_sha256 AND verified_size = declared_size)),
  CHECK(state <> 'committed' OR verified_sha256 IS NOT NULL),
  CHECK((materialization_placement_id IS NULL AND materialization_binding_id IS NULL)
     OR (materialization_placement_id IS NOT NULL AND materialization_binding_id IS NOT NULL
         AND materialization_placement_id > 0 AND materialization_binding_id > 0)),
  CHECK(state <> 'committed' OR oci_upload_id IS NULL
     OR (materialization_placement_id IS NOT NULL AND materialization_binding_id IS NOT NULL))
);
