-- Companion outputs are first-class members of the authenticated release and
-- live-catalog closures. Rebuild the two projection tables so existing Hub
-- databases admit the same closed artifact vocabulary as fresh installs.
ALTER TABLE release_artifacts RENAME TO release_artifacts_before_companions;
CREATE TABLE release_artifacts(
  snapshot_id KEYTEXT64 NOT NULL,
  release_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  metadata_digest KEYTEXT128 NOT NULL,
  CHECK(artifact_kind IN(
    'output', 'image', 'source_derivation', 'expose', 'config',
    'evaluation_base_lib', 'documentation'
  )),
  PRIMARY KEY(snapshot_id, package_name, package_version, platform,
artifact_kind, store_hash),
  FOREIGN KEY(snapshot_id, release_id, registry_id)
  REFERENCES release_artifact_snapshots(snapshot_id, release_id, registry_id)
);
INSERT INTO release_artifacts(
  snapshot_id, release_id, registry_id, package_name, package_version,
  platform, artifact_kind, store_path, store_hash, metadata_digest
)
SELECT snapshot_id, release_id, registry_id, package_name, package_version,
       platform, artifact_kind, store_path, store_hash, metadata_digest
FROM release_artifacts_before_companions;
DROP TABLE release_artifacts_before_companions;
CREATE INDEX release_artifacts_hash_idx
ON release_artifacts(store_hash, snapshot_id);

ALTER TABLE registry_catalog_artifacts
RENAME TO registry_catalog_artifacts_before_companions;
CREATE TABLE registry_catalog_artifacts(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  source_revision KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  artifact_kind KEYTEXT32 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  metadata_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, source_revision, package_name, package_version,
platform, artifact_kind, store_hash),
  CHECK(artifact_kind IN(
    'output', 'image', 'source_derivation', 'expose', 'config',
    'evaluation_base_lib', 'documentation'
  ))
);
INSERT INTO registry_catalog_artifacts(
  registry_id, source_revision, package_name, package_version, platform,
  artifact_kind, store_path, store_hash, metadata_digest
)
SELECT registry_id, source_revision, package_name, package_version, platform,
       artifact_kind, store_path, store_hash, metadata_digest
FROM registry_catalog_artifacts_before_companions;
DROP TABLE registry_catalog_artifacts_before_companions;
CREATE INDEX registry_catalog_artifacts_hash_idx
ON registry_catalog_artifacts(registry_id, source_revision, store_hash);

CREATE TABLE package_documentation(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  indexed_commit KEYTEXT64 NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  platform TEXT NOT NULL,
  format KEYTEXT64 NOT NULL,
  store_path TEXT NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  document_sha256 KEYTEXT128 NOT NULL,
  document_size INTEGER NOT NULL,
  semantic_schema_sha256 KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, package_name, package_version, platform),
  CHECK(format = 'aos.package-documentation/v1+json'),
  CHECK(nar_size > 0 AND nar_size <= 4194304),
  CHECK(document_size > 0 AND document_size <= 4194304)
);
CREATE INDEX package_documentation_digest_idx
ON package_documentation(registry_id, document_sha256);
CREATE TABLE package_documentation_search(
  registry_id INTEGER NOT NULL,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  platform TEXT NOT NULL,
  kind KEYTEXT16 NOT NULL,
  document_key TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  terms LONGTEXT NOT NULL,
  PRIMARY KEY(
    registry_id, package_name, package_version, platform, kind, document_key
  ),
  FOREIGN KEY(registry_id, package_name, package_version, platform)
    REFERENCES package_documentation(
      registry_id, package_name, package_version, platform
    ) ON DELETE CASCADE,
  CHECK(kind IN('package', 'option', 'service', 'credential', 'capability'))
);
CREATE INDEX package_documentation_search_package_idx
ON package_documentation_search(registry_id, package_name, package_version, platform);
