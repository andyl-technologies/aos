-- Marks complete per-commit projections, including commits with no ability companions.
CREATE TABLE package_ability_reference_catalogs(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  indexed_commit KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, indexed_commit)
);

-- Retains bounded public references derived from signed package ability companions.
CREATE TABLE package_ability_references(
  registry_id INTEGER NOT NULL,
  indexed_commit KEYTEXT64 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  manifest_sha256 KEYTEXT128 NOT NULL,
  package_digest KEYTEXT128 NOT NULL,
  canonical_json BLOB NOT NULL,
  PRIMARY KEY(registry_id, indexed_commit, package_name, package_version, platform),
  FOREIGN KEY(registry_id, indexed_commit)
    REFERENCES package_ability_reference_catalogs(registry_id, indexed_commit)
    ON DELETE CASCADE,
  CHECK(length(canonical_json) > 0 AND length(canonical_json) <= 4194304)
);
