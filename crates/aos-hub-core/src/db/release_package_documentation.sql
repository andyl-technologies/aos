-- A live catalog may stop advertising a package while an immutable signed
-- release still roots its artifacts. Retain the complete documentation
-- locator beside that exact release snapshot so digest-addressed reads remain
-- provenance-correct without retaining mutable search projections.
CREATE TABLE release_package_documentation(
  snapshot_id KEYTEXT64 NOT NULL,
  release_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL DEFAULT 'documentation',
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  format KEYTEXT64 NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  document_sha256 KEYTEXT128 NOT NULL,
  document_size INTEGER NOT NULL,
  semantic_schema_sha256 KEYTEXT128 NOT NULL,
  system_module_nar_hash KEYTEXT128,
  metadata_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(snapshot_id, package_name, package_version, platform),
  CHECK(artifact_kind = 'documentation'),
  CHECK(format = 'aos.package-documentation/v1+json'),
  CHECK(nar_size > 0 AND nar_size <= 4194304),
  CHECK(document_size > 0 AND document_size <= 4194304),
  FOREIGN KEY(snapshot_id, release_id, registry_id)
    REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
    ON DELETE CASCADE,
  FOREIGN KEY(snapshot_id, package_name, package_version, platform,
              artifact_kind, store_hash)
    REFERENCES release_artifacts(snapshot_id, package_name, package_version,
                                 platform, artifact_kind, store_hash)
    ON DELETE CASCADE
);
CREATE INDEX release_package_documentation_digest_idx
ON release_package_documentation(registry_id, document_sha256);
