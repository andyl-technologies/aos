-- Disposable native search rows derived from authenticated module references.
CREATE TABLE release_native_documentation(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  package_version KEYTEXT64 NOT NULL,
  platform KEYTEXT64 NOT NULL,
  document_sha256 KEYTEXT128 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  search_json LONGTEXT NOT NULL,
  content_digest KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, source_commit, package_name, package_version, platform),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);
