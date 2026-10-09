-- Disposable release-wide ability graphs derived from the exact checked
-- package references retained by the authenticated browse catalog.
CREATE TABLE release_ability_graphs(
  registry_id INTEGER NOT NULL,
  source_commit KEYTEXT64 NOT NULL,
  platform KEYTEXT255 NOT NULL,
  canonical_json LONGTEXT NOT NULL,
  content_digest KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, source_commit, platform),
  FOREIGN KEY(registry_id, source_commit)
    REFERENCES release_browse_catalogs(registry_id, source_commit) ON DELETE CASCADE
);
